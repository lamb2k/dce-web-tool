#include "browser_ethernet_queue.h"
#include <cassert>
#include <iostream>
int main() {
    using namespace halo_browser;
    Queue q; std::array<uint8_t,MaxFrame> p{}; p[12]=8;
    assert(!q.push(1,p.data(),14,0)); auto gen=q.configure();
    assert(!q.push(gen,p.data(),13,0)); assert(!q.push(gen,p.data(),1515,0));
    p[12]=0x81; assert(!q.push(gen,p.data(),14,0));p[12]=8;
    for(unsigned i=0;i<MaxFrames;i++) assert(q.push(gen,p.data(),MaxFrame,0));
    assert(q.bytes==48448 && q.highWater==32); assert(!q.push(gen,p.data(),14,0));
    unsigned called=0;q.drain(2,[&](const uint8_t*,unsigned){++called;return false;});assert(called==1&&q.count==32);
    q.drain(1001,[&](const uint8_t*,unsigned){assert(false);return true;}); assert(q.count==0&&q.bytes==0);
    assert(q.push(gen,p.data(),14,1002));p[0]=99;
    q.drain(1003,[&](const uint8_t* f,unsigned n){assert(n==14&&f[0]==0);return true;});
    q.stop(); assert(!q.push(gen,p.data(),14,1004));auto next=q.configure();assert(next!=gen);
    assert(!q.push(gen,p.data(),14,1004));assert(q.push(next,p.data(),14,1004));q.stop();assert(!q.count);
    std::cout << "Queue " << sizeof(Queue) << " Frame " << sizeof(Frame) << " payload48448 PASS\n";
}
