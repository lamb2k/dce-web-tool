// Tests compile the production service, with only JS/config/device edges stubbed.
#include <cassert>
#include <cstring>
#include <iostream>
#include "browser_ethernet.cpp"
namespace config { bool EmulateBBA=false; }
namespace {
unsigned sent=0, delivered=0, closeCalls=0;
uint32_t lastTxGeneration=0;
bool reenter=false;
int browser_tx(const uint8_t*, unsigned n, uint32_t gen) {
    assert(n==42); assert(gen==halo_eth_metric(0));
    ++sent; lastTxGeneration=gen; return 1;
}
void browser_stop(uint32_t) {
    ++closeCalls;
    if(reenter) {
        assert(halo_eth_configure()==0);
        assert(!halo_eth_rx(halo_eth_metric(0),42));
        halo_eth_stop(); // Must not recursively notify JS.
    }
}
}
double emscripten_get_now() { return 100; }
int bba_recv_frame(const uint8_t*,uint32_t n) { assert(n==42);++delivered;return 1; }
int main() {
    net::modbba::BrowserEthernetService service;
    uint8_t frame[42]{};frame[12]=8;frame[13]=6;
    std::memcpy(halo_eth_rx_buffer(),frame,sizeof(frame));
    assert(!service.start());auto initial=halo_eth_configure();
    assert(!halo_eth_rx(initial,sizeof(frame)));
    service.receiveEthFrame(frame,sizeof(frame));net::modbba::browserEthernetDrain();
    assert(!sent&&!delivered&&!halo_eth_metric(7));
    halo_eth_stop();config::EmulateBBA=true;
    assert(!service.start());assert(halo_eth_metric(7)==1&&!halo_eth_metric(8));
    auto first=halo_eth_configure(); // Device started before lease.
    assert(halo_eth_rx(first,sizeof(frame)));net::modbba::browserEthernetDrain();
    service.receiveEthFrame(frame,sizeof(frame));assert(sent==1&&delivered==1&&lastTxGeneration==first);
    assert(halo_eth_rx(first,sizeof(frame)));halo_eth_stop();
    assert(halo_eth_metric(7)==1&&!halo_eth_metric(8)&&!halo_eth_metric(1));
    service.receiveEthFrame(frame,sizeof(frame));assert(sent==1);
    assert(!halo_eth_rx(first,sizeof(frame)));
    auto second=halo_eth_configure();assert(second!=first); // No second start call.
    assert(!halo_eth_rx(first,sizeof(frame)));
    assert(halo_eth_rx(second,sizeof(frame)));net::modbba::browserEthernetDrain();
    service.receiveEthFrame(frame,sizeof(frame));assert(sent==2&&delivered==2&&lastTxGeneration==second);
    service.stop();assert(!halo_eth_metric(7)&&!halo_eth_metric(8));
    auto afterCoreStop=halo_eth_configure();
    assert(!halo_eth_rx(afterCoreStop,sizeof(frame)));
    service.receiveEthFrame(frame,sizeof(frame));net::modbba::browserEthernetDrain();assert(sent==2&&delivered==2);
    assert(service.start());assert(halo_eth_rx(afterCoreStop,sizeof(frame)));net::modbba::browserEthernetDrain();
    service.receiveEthFrame(frame,sizeof(frame));assert(sent==3&&delivered==3);
    const unsigned beforeClose=closeCalls;reenter=true;halo_eth_stop();reenter=false;
    assert(closeCalls==beforeClose+1&&!halo_eth_metric(8)&&halo_eth_metric(7)==1);
    auto afterReentry=halo_eth_configure();assert(afterReentry);assert(halo_eth_rx(afterReentry,sizeof(frame)));
    reenter=true;net::modbba::browserEthernetInvalidate();reenter=false;
    assert(!halo_eth_metric(7)&&!halo_eth_metric(8)&&!halo_eth_metric(1));
    auto finalLease=halo_eth_configure();assert(finalLease&&!halo_eth_rx(finalLease,sizeof(frame)));
    service.receiveEthFrame(frame,sizeof(frame));assert(sent==3);
    assert(service.readModem()==-1&&service.modemAvailable()==0);
    std::cout<<"Production service reconnect/reentry PASS; known state "<<halo_eth_metric(6)<<" B\n";
}
