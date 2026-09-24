"""Source-derived element/serialization counts, NOT heap capacity or RSS sizes."""
import json
from pathlib import Path
P=4096
Q=1<<20
O=21

def bitmap(n, maximum):
    h=1
    c=maximum
    while c>64:
        c=(c+63)//64;h+=1
    levels=[]
    for _ in range(h):
        levels.append(n);n=(n+63)//64
    words=sum((n+63)//64 for n in levels)
    return {'levels':h,'words':words,'serialized_bytes':4+8*h+8*words}

def buddy(n):
    shapes=[bitmap(n>>o,Q>>o) for o in range(O)]
    return {'bitmaps':O,'levels':sum(x['levels'] for x in shapes),'words':sum(x['words'] for x in shapes),'serialized_bytes':8+4*O+sum(x['serialized_bytes'] for x in shapes)}

def shape(d):
    if type(d) is not int or not (P <= d <= P*Q*(1<<20)):
        raise ValueError("unsupported extent for this source-shape audit")
    n=(d+P-1)//P
    counts=[]
    left=n
    while left:
        take=min(left,Q);counts.append(buddy(take));left-=take
    regions=len(counts)
    tracker=bitmap(max(1000,regions),1<<20)
    return {'logical_extent_cap':d,'conservative_base_page_slots':n,'conservative_regions':regions,'buddy_bitmap_objects':sum(x['bitmaps'] for x in counts),'buddy_level_objects':sum(x['levels'] for x in counts),'buddy_word_elements':sum(x['words'] for x in counts),'buddy_word_payload_bytes':8*sum(x['words'] for x in counts),'all_buddy_serialized_bytes':sum(x['serialized_bytes'] for x in counts),'largest_buddy_serialized_bytes':max(x['serialized_bytes'] for x in counts),'tracker_bitmap_objects':O,'tracker_level_objects':O*tracker['levels'],'tracker_word_elements':O*tracker['words'],'tracker_serialized_bytes':4+4*O+O*tracker['serialized_bytes'],'warning':'Counts only. Region/header overhead is ignored conservatively in page count. Vec/HashMap capacity, layouts, native locks, allocation headers, clones, scratch and error payloads are not this number.'}
result={'status':'PURE_SOURCE_DERIVED_SHAPES_NOT_TOTAL_WORKSPACE','constants':{'page_bytes':P,'maximum_region_pages':Q,'orders':O,'initial_region_tracker_slots':1000},'cases':[shape(x) for x in [64<<20,256<<20,1<<30,8<<30,1<<40]]}
Path(__file__).with_name('allocator-shape.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
