"""Checked requested-layout arithmetic, using the frozen native geometry inputs.
This is a cache collection component, not total cache/table/RSS admission.
"""
from pathlib import Path
import hashlib,json
MAX=(1<<64)-1
MAX_LAYOUT=(1<<63)-1

def checked(value):
    if not 0 <= value <= MAX: raise OverflowError(value)
    return value

def add(a,b): return checked(a+b)
def mul(a,b): return checked(a*b)
def ceildiv(a,b):
    checked(a)
    if not b: raise ZeroDivisionError
    return add(a//b,int(a%b!=0))
def nextpow(a):
    checked(a)
    return checked(1 << (a-1).bit_length())
def block(size):
    if size>MAX_LAYOUT: raise OverflowError(size)
    return {'bytes':size,'allocations':int(size!=0)}
def plus(a,b): return {'bytes':add(a['bytes'],b['bytes']),'allocations':add(a['allocations'],b['allocations'])}
def times(a,n): return {'bytes':mul(a['bytes'],n),'allocations':mul(a['allocations'],n)}
def charge(a,overhead): return add(a['bytes'],mul(a['allocations'],overhead))

def hash_layout(n,group=8):
    # frozen geometry::hash<(u64,(Arc<[u8]>,AtomicBool))>; Option<Arc> same32/8.
    if not n: return block(0)
    if group not in (8,16): raise ValueError(group)
    cap=mul(n,2)
    if cap<15:
        cap=max(cap,3)
        buckets=4 if cap<4 else 8 if cap<8 else 16
    else: buckets=nextpow(mul(cap,8)//7)
    align=max(8,group)
    data=mul(32,buckets)
    offset=add(data,align-1)&~(align-1)
    return block(add(add(offset,buckets),group))

def queue_layout(n):
    # frozen geometry::vector::<u64>: cap<=max(2*n,4).
    return block(mul(max(mul(n,2),4),8)) if n else block(0)

def profile(cache_bytes,page_bytes,depth=128,stripes=131):
    read=max(ceildiv(ceildiv(cache_bytes,page_bytes),stripes),1)
    write=add(add(read,depth),4)
    rh=hash_layout(read);rq=queue_layout(read);wh=hash_layout(write);wq=queue_layout(write)
    retained=times(plus(plus(rh,rq),plus(wh,wq)),stripes)
    peak=times(retained,2)
    return {'input_cache_bytes':cache_bytes,'input_page_bytes':page_bytes,'input_depth':depth,'input_stripes':stripes,'read_entries_per_stripe':read,'write_entries_per_stripe':write,'read_hash_per_stripe':rh,'read_queue_per_stripe':rq,'write_hash_per_stripe':wh,'write_queue_per_stripe':wq,'retained_collection_layouts':retained,'all_old_new_reallocation_overlap':peak,'retained_with_existing_4096_policy_allowance':charge(retained,4096),'overlap_with_existing_4096_policy_allowance':charge(peak,4096)}

def tests():
    assert ceildiv(MAX,MAX)==1
    assert ceildiv(MAX,2)==1<<63
    for operation in [lambda:add(MAX,1),lambda:mul(MAX,2),lambda:block(MAX),lambda:hash_layout(MAX),lambda:profile(MAX,1)]:
        try: operation()
        except OverflowError: pass
        else: raise AssertionError('overflow admitted')
    assert hash_layout(16)=={'bytes':2120,'allocations':1}
    assert hash_layout(148)=={'bytes':16904,'allocations':1}
    assert queue_layout(16)=={'bytes':256,'allocations':1}
    assert queue_layout(148)=={'bytes':2368,'allocations':1}
    assert profile(8<<20,4096)['retained_collection_layouts']=={'bytes':2835888,'allocations':524}

def main():
    tests()
    here=Path(__file__).resolve().parent
    result=profile(8<<20,4096)
    output={'status':'DERIVED_COMPONENT_FROM_FROZEN_NATIVE_LAYOUTS_NOT_A_NEW_NATIVE_OR_RSS_MEASUREMENT','target':'aarch64-apple-darwin','rustc':'1.97.1 8bab26f4f68e0e26f0bb7960be334d5b520ea452','group_width':8,'hash_entry_size':32,'hash_entry_alignment':8,'queue_entry_size':8,'maximum_bits':64,'per_table':result,'two_custody_tables':{'retained_collection_layouts':times(result['retained_collection_layouts'],2),'all_old_new_reallocation_overlap':times(result['all_old_new_reallocation_overlap'],2),'retained_with_existing_4096_policy_allowance':mul(result['retained_with_existing_4096_policy_allowance'],2),'overlap_with_existing_4096_policy_allowance':mul(result['overlap_with_existing_4096_policy_allowance'],2)},'not_included':['fixed cache/stripe Vec and Arc owners and native synchronization allocations','page payloads and guard-retained or concurrently missed payloads','allocator copies, transaction/debug/free-page collections','store/backend/spool/worker/census ownership','actual allocator metadata or RSS qualification'],'python_arithmetic_assertions':'PASS'}
    (here/'components.json').write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps(output,indent=2))
if __name__=='__main__':main()
