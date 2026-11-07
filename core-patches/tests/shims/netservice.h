#pragma once
#include <cstdint>
using u8=uint8_t; using u32=uint32_t;
namespace net::modbba {
class Service {
public:
 virtual ~Service()=default;
 virtual bool start()=0; virtual void stop()=0;
 virtual void writeModem(u8)=0; virtual int readModem()=0; virtual int modemAvailable()=0;
 virtual void receiveEthFrame(const u8*,u32)=0;
};
}
