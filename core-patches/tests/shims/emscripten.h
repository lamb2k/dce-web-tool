#pragma once
#define EMSCRIPTEN_KEEPALIVE
#define EM_JS(ret,name,args,...) ret name args
double emscripten_get_now();
