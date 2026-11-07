"""The public sign-up policy, one for every route that can create a public key (S2-8).

public_enroll.py (console and tester kit) and the browser route in server.py both call it. It holds the refused list,
the caps on new identities per client group per day, and the total per day. The total lives on disk, locked, so the
two services share one count. A group's count is RAM only: a tag, never an address.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import time

try:
    import fcntl
except ImportError:   # Windows host tests; the services run on Linux
    fcntl = None

from enrollment import EnrollmentError, key_id, valid_public

PER_CLIENT_DAY = 3      # new identities per browser client tag per day (the Worker's address group)


class EnrollmentPolicy:
    def __init__(self, state, revoked, daily, clock=time.time):
        self.state, self.revoked, self.daily, self.clock = Path(state), Path(revoked), daily, clock
        self.salt = secrets.token_bytes(32)
        self.new_today = {}
        self.day = self.today()

    def today(self):
        return datetime.datetime.fromtimestamp(self.clock(), datetime.timezone.utc).strftime('%Y-%m-%d')

    def group_tag(self, name):
        return hashlib.sha256(self.salt+name.encode()).digest()[:12]

    def is_revoked(self, public):
        try:
            return key_id(public) in self.revoked.read_text().split()
        except FileNotFoundError:
            return False   # no key revoked yet
        except OSError as exc:
            raise EnrollmentError(503) from exc   # never fail open on a list we cannot read

    def locked_count(self, add=0):
        """The shared total for today, optionally raised, under a lock on a sibling file."""
        with open(str(self.state)+'.lock', 'a') as lock:
            if fcntl:
                fcntl.flock(lock, fcntl.LOCK_EX)
            today = self.today()
            try:
                value = json.loads(self.state.read_text())
                day, count = value['day'], int(value['count'])
            except (OSError, ValueError, KeyError, TypeError):
                day, count = today, 0
            changed = day != today or add
            if day != today:
                day, count = today, 0
            count += add
            if changed:
                self.write(day, count)
            return count

    def write(self, day, count):
        temp = str(self.state)+f'.{os.getpid()}.new'
        with open(temp, 'w') as f:
            json.dump({'day': day, 'count': count}, f)
        os.replace(temp, self.state)

    def roll(self):
        if self.today() != self.day:
            self.day = self.today()
            self.new_today.clear()

    def check(self, public, groups):
        """groups: [(tag, cap per day)]. Raises EnrollmentError unless this key may go on. Spends nothing."""
        self.roll()
        if not valid_public(public):
            raise EnrollmentError(400)
        if self.is_revoked(public):
            raise EnrollmentError(403)
        if self.locked_count() >= self.daily or any(self.new_today.get(tag, 0) >= day for tag, day in groups):
            raise EnrollmentError(429)

    def record(self, value, groups):
        """After a register reply: count it only when the key is new."""
        if value.get('created') is True:
            self.locked_count(1)
            for tag, _ in groups:
                self.new_today[tag] = self.new_today.get(tag, 0)+1


class GuardedEnrollment:
    """EnrollmentRelay's handle(), with the policy in front, for the browser route. No client tag, no public key."""

    def __init__(self, relay, policy):
        self.relay, self.policy = relay, policy

    async def handle(self, action, session, session_expiry, body, client=None):
        if action == 'config':
            return await self.relay.handle(action, session, session_expiry, body)
        if not client:
            raise EnrollmentError(403)
        if not isinstance(body, dict):
            raise EnrollmentError(400)
        caps = [(self.policy.group_tag('browser:'+client), PER_CLIENT_DAY)]
        self.policy.check(body.get('publicKey'), caps)
        value = await self.relay.handle(action, session, session_expiry, body)
        if action == 'register':
            self.policy.record(value, caps)
        return value
