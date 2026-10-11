import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from linuxhound.checkpoint import load_checkpoint,save_checkpoint


def main():
    p=argparse.ArgumentParser();p.add_argument('checkpoint');p.add_argument('--output',required=True);a=p.parse_args()
    checkpoint=load_checkpoint(a.checkpoint);save_checkpoint(a.output,checkpoint)
    if load_checkpoint(a.output)!=checkpoint:raise ValueError('converted weights differ from the source checkpoint')
    print('Checkpoint converted and exact float32 weights verified. No retraining.')
if __name__=='__main__':main()
