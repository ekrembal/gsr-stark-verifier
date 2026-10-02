// Differential test of the optional pinned CPU evaluator and its C ABI.
// Compile with the same native vector flags as kernels/cxx_batch; link both
// original scalar and optional packed SDK static libraries. See the report.
#include "packed_fpext.h"
#include <array>
#include <vector>
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <cstring>
#include <type_traits>
namespace risc0::circuit::rv32im_v2 {
FpExt poly_fp(size_t,size_t,FpExt*,Fp**);
}
extern "C" bool risc0_circuit_rv32im_cpu_poly_fp_batch_available();
extern "C" const char* risc0_circuit_rv32im_cpu_poly_fp_batch(
    size_t, size_t, const risc0::FpExt*, const risc0::Fp* const*, risc0::FpExt*);
int main() {
 if (!risc0_circuit_rv32im_cpu_poly_fp_batch_available())
  throw std::runtime_error("native polynomial batch implementation not linked");
 using risc0::Fp; using risc0::FpExt;
 uint64_t random=0x123456789abcdef0ULL;
 auto next=[&](){random^=random<<13;random^=random>>7;random^=random<<17;return Fp(uint32_t(random%Fp::P));};
 std::vector<FpExt> mixes(4096);
 for(auto& m:mixes)m=FpExt(next(),next(),next(),next());
 static_assert(sizeof(Fp)==sizeof(uint32_t) && std::is_trivially_copyable_v<Fp>);
 auto raw_fp=[](uint32_t word){Fp x; std::memcpy(&x,&word,sizeof word);return x;};
 size_t arithmetic=0;
 for(size_t round=0;round<4096;++round){
  std::array<Fp,8>a,b;
  const uint32_t edge[8]={0,1,Fp::P-1,Fp::P,Fp::P+1,UINT32_MAX,UINT32_MAX-1,0x80000000u};
  for(size_t i=0;i<8;++i){
   random^=random<<13;random^=random>>7;random^=random<<17;
   a[i]=raw_fp(round%2?uint32_t(random):edge[i]);
   random^=random<<13;random^=random>>7;random^=random<<17;
   b[i]=raw_fp(round%2?uint32_t(random):edge[7-i]);
  }
  auto aa=gsr_poly_batch::Fp::load(a.data(),[](size_t i){return i;});
  auto bb=gsr_poly_batch::Fp::load(b.data(),[](size_t i){return i;});
  auto sum=aa+bb, diff=aa-bb, prod=aa*bb;
  for(size_t i=0;i<8;++i){
   if(sum.raw(i)!=(a[i]+b[i]).asRaw() || diff.raw(i)!=(a[i]-b[i]).asRaw() || prod.raw(i)!=(a[i]*b[i]).asRaw()){
    std::fprintf(stderr,"Arithmetic mismatch round=%zu lane=%zu\n",round,i);return 2;
   }
   ++arithmetic;
  }
 }
 size_t cases=0;
 for(size_t pattern=0;pattern<3;++pattern) for(size_t steps:{1,2,4,8,64,128,512}) {
  std::array<std::vector<Fp>,4> storage;
  std::array<Fp*,4> args;
  for(size_t i=0;i<4;++i){storage[i].resize(1024*steps);for(auto& x:storage[i])x=pattern==0?Fp(0):(pattern==1?raw_fp(Fp::P-1):next());args[i]=storage[i].data();}
  for(size_t cycle:{size_t(0),size_t(1),size_t(4),size_t(7),steps-8,steps-4,steps-1}) {
   auto packed=gsr_poly_batch::poly_fp(cycle,steps,{mixes.data()},args.data());
   std::array<FpExt,10> abi;
   const FpExt sentinel(Fp(11),Fp(23),Fp(47),Fp(97));
   abi.fill(sentinel);
   auto inputs_before=storage;
   auto mixes_before=mixes;
   if (auto error=risc0_circuit_rv32im_cpu_poly_fp_batch(cycle,steps,mixes.data(),args.data(),&abi[1]))
    throw std::runtime_error(error);
   if (abi[0]!=sentinel || abi[9]!=sentinel || storage!=inputs_before || mixes!=mixes_before)
    throw std::runtime_error("ABI canary or readonly input changed");
   for(size_t lane=0;lane<8;++lane) {
    auto scalar=risc0::circuit::rv32im_v2::poly_fp(cycle+lane,steps,mixes.data(),args.data());
    for(size_t i=0;i<4;++i)if(packed.elems[i].raw(lane)!=scalar.elems[i].asRaw() || abi[lane+1].elems[i].asRaw()!=scalar.elems[i].asRaw()) {
     std::fprintf(stderr,"Mismatch steps=%zu cycle=%zu lane=%zu component=%zu\n",steps,cycle,lane,i);return 1;
    }
    ++cases;
   }
  }
 }
 const size_t steps=2048;
 std::array<std::vector<Fp>,4> storage;
 std::array<Fp*,4> args;
 for(size_t i=0;i<4;++i){storage[i].resize(1024*steps);for(auto& x:storage[i])x=next();args[i]=storage[i].data();}
 std::vector<std::array<uint32_t,4>> expected(steps);
 volatile uint64_t checksum=0;
 for(int sample=0;sample<3;++sample) {
  auto start=std::chrono::steady_clock::now();
  for(size_t cycle=0;cycle<steps;++cycle){auto x=risc0::circuit::rv32im_v2::poly_fp(cycle,steps,mixes.data(),args.data());checksum=checksum+x.elems[0].asRaw();for(size_t k=0;k<4;++k)expected[cycle][k]=x.elems[k].asRaw();}
  double scalar=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
  start=std::chrono::steady_clock::now();
  for(size_t cycle=0;cycle<steps;cycle+=8){auto x=gsr_poly_batch::poly_fp(cycle,steps,{mixes.data()},args.data());for(size_t lane=0;lane<8;++lane){checksum=checksum+x.elems[0].raw(lane);for(size_t k=0;k<4;++k)if(x.elems[k].raw(lane)!=expected[cycle+lane][k])throw std::runtime_error("benchmark differential mismatch");}}
  double packed=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
  std::printf("{\"sample\":%d,\"differential_points\":%zu,\"rows\":%zu,\"scalar_seconds\":%.9f,\"packed_seconds\":%.9f,\"speedup\":%.6f}\n",sample,cases,steps,scalar,packed,scalar/packed);
 }
 std::printf("arithmetic_lanes=%zu benchmark_points=%zu checksum=%llu\n",arithmetic,3*steps,(unsigned long long)checksum);
}
