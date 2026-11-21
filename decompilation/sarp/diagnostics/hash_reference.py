"""Independent arithmetic-only check of reached SARP hash-gate proofs."""
import json
import re
import struct
from pathlib import Path
import reference

M=(1<<32)-1
def u(v):return v&M
def rol(v,n):return u((u(v)<<n)|(u(v)>>(32-n)))
def ror(v,n):return rol(v,32-n)
def swap(v):return int.from_bytes(u(v).to_bytes(4,"little"),"big")
def lz(v):return 32-u(v).bit_length()
def tz(v):return (u(v)&-u(v)).bit_length()-1 if u(v) else 32

def calculate(x,mask,key,pool):
    a,b,c=reference.build_permutations()
    def A(v):return a[v&16383]
    def B(v):return b[v&16383]
    def C(v):return c[v&16383]
    w0=u(x^mask^pool^12836);w1=w0^(w0>>15)
    a1,a2=A(w1),B(w1>>14);a3=C((w1>>18)^a1^a2)
    h1=u(w1*108439+rol(w0,10)+a1*65537+a2+key)^rol(a3,23)
    t2=h1^rol(h1,14)^mask;b1,b2=A(t2),B(t2>>14);b3=C(t2^b1^b2)
    h2=u(t2*70859+b1*65537+b2*257+b3+key)^ror(h1,10)
    t3=h2^h1^rol(w0,23);c1,c2=A(t3),B(t3>>14);c3=C(h2^c1^c2)
    h3=u(t3*113129+c1*65537+c2*257+c3+lz(w0)*131+tz(h1)*17)^swap(h2)
    t4=h3^rol(h2,10)^mask;d1,d2=A(t4),B(t4>>14);d3=C(h3^d1^d2)
    hr,tr=h3,t4
    for j in range(1,61):
        lo,hi=struct.unpack("<II",struct.pack("<d",tr+hr/1024+j))
        s1,s2=A(tr^lo),B((tr>>14)^hi);s3=C(hr^s1^s2)
        nh=u(tr*108439+hr+s1*65537+s2*257+s3+lz(tr)*29+tz(hr)*19+j*997)^rol(hr,23)^swap(s3)^lo
        tr=u(nh^ror(tr,14)^mask^key^hi);hr=nh
    pk1=u(hr*113129+d1*65537+d3+mask)^rol(d2,14)^ror(h1,23)^tr
    pk2=u(tr*108439+hr+d2*65537+d1+key)^rol(d3,10)^ror(b3,14)^h3
    kvip=u((hr^d3^rol(c1,13))+b2*65537)
    kvsh=u((tr^d1^ror(c2,11))+b1*65537)
    return pk1,pk2,kvip,kvsh

def main():
    directory=Path(__file__).resolve().parent
    listing=(directory.parent/"target.bytecode.txt").read_text()
    rows=[]
    for body in re.findall(r"HashProof \{([^}]+)\}",listing):
        fields={k:int(v) for k,v in re.findall(r"(\w+): (\d+)",body)}
        got=calculate(fields["value"],fields["mask"],fields["key"],fields["pool"])
        expected=tuple(fields[k] for k in ["pk1","pk2","kv_ip","kv_sh"])
        assert got==expected,(fields,got,expected)
        rows.append({"input":fields,"reference":got,"matches":True})
    assert rows,"No reached hash proofs found"
    (directory/"hash-reference-results.json").write_text(json.dumps(rows,indent=2)+"\n")
    print(f"PASS: {len(rows)} reached constant hash-gate proofs match independently transcribed arithmetic.")

if __name__=="__main__":main()
