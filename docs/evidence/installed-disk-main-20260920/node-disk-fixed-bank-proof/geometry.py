"""Checked pinned-layout arithmetic only; this does not run or model HashMap."""
import json
MAX = (1 << 64) - 1
ISIZE_MAX = (1 << 63) - 1

def add(a, b):
    value = a + b
    if value > MAX: raise OverflowError
    return value

def mul(a, b):
    value = a * b
    if value > MAX: raise OverflowError
    return value

def requested(capacity, size, align, group):
    if not capacity: return dict(buckets=0, usable=0, bytes=0, allocations=0)
    assert group in (8, 16) and align and align & (align-1) == 0
    if capacity < 15:
        minimum = 14 if group == 16 and size <= 1 else 7 if (group == 16 and size <= 3) or (group == 8 and size <= 1) else 3
        cap = max(capacity, minimum)
        buckets = 4 if cap < 4 else 8 if cap < 8 else 16
    else:
        adjusted = mul(capacity, 8) // 7
        buckets = 1 << (adjusted-1).bit_length()
        if buckets > MAX: raise OverflowError
    control_align = max(align, group)
    offset = add(mul(size, buckets), control_align-1) & ~(control_align-1)
    length = add(offset, add(buckets, group))
    if length > ISIZE_MAX-(control_align-1): raise OverflowError
    usable = buckets-1 if buckets < 8 else buckets//8*7
    assert usable >= capacity
    return dict(buckets=buckets, usable=usable, bytes=length, allocations=1)

for c in [0,1,3,4,7,8,14,15,28,29,4096,16384,32769,1000001,2000001]:
    for size,align in [(24,8),(112,8),(128,64),(1,1)]:
        for group in (8,16):
            result=requested(c,size,align,group)
            assert result['usable'] >= c
for c,size,align in [(MAX,112,8),(1<<60,112,8)]:
    try: requested(c,size,align,8)
    except OverflowError: pass
    else: raise AssertionError('overflow accepted')

N,R,H=1000000,1,4096
C=add(mul(2,N),R)
record=requested(C,112,8,8)
live=requested(H,24,8,8)
old_ledger=add(add(mul(mul(C,4),128),4096),add(mul(mul(add(N,R),4),128),4096))
old_live=add(mul(mul(H,4),40),4096)
print(json.dumps({
 'status':'CHECKED_ARITHMETIC_ONLY_NOT_NATIVE_LAYOUT_OR_ALLOCATOR_QUALIFICATION',
 'conditional_type_inputs':{'inode_pair_size':112,'inode_pair_align':8,'live_pair_size':24,'live_pair_align':8,'group_width':8},
 'policy':{'N':N,'R':R,'H':H,'inode_physical_capacity_each':C,'census_logical_capacity':N+R},
 'inode_each_bank':record,'inode_two_banks_requested':2*record['bytes'],
 'live_each_bank':live,'live_two_banks_requested':2*live['bytes'],
 'four_banks_requested':2*(record['bytes']+live['bytes']),
 'old_estimated_ledger_component':old_ledger,'old_estimated_live_component':old_live,
 'component_reduction_conditional':old_ledger+old_live-2*(record['bytes']+live['bytes']),
 'new_inline_objects_and_native_allocator_allowance_excluded':True,
 'assertions':'PASS'
},indent=2))
