#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import random
import multiprocessing
import argparse

def run_fuzz_iteration(binary_path, target):
    # Generate random data (size 1 to 4096 bytes)
    size = random.randint(1, 4096)
    data = os.urandom(size)
    
    env = os.environ.copy()
    env["FUZZ"] = target
    
    try:
        # Run the binary with the data on stdin
        p = subprocess.Popen(
            [binary_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env
        )
        stdout, stderr = p.communicate(input=data)
        
        if p.returncode != 0:
            # Crash detected
            print(f"\nCRASH! Return code: {p.returncode}")
            print(f"Target: {target}")
            print(f"Input (hex): {data.hex()}")
            print(f"Stderr: {stderr.decode('utf-8', errors='replace')}")
            # Save crash to file
            with open(f"crash_{int(time.time())}.bin", "wb") as f:
                f.write(data)
            return False
    except Exception as e:
        print(f"Execution failed: {e}")
        return False
        
    return True

def worker(args):
    binary_path, target, end_time = args
    # Seed random generator for this process
    random.seed()
    
    while time.time() < end_time:
        if not run_fuzz_iteration(binary_path, target):
            return False
    return True

def main():
    parser = argparse.ArgumentParser(description="Standalone fuzzer wrapper")
    parser.add_argument("target", help="Fuzz target name")
    parser.add_argument("-max_total_time", type=int, default=60, help="Duration in seconds")
    parser.add_argument("-jobs", type=int, default=1, help="Number of parallel jobs")
    parser.add_argument("-workers", type=int, default=1, help="Ignored (compatibility)")
    
    # Parse known args, ignore others
    args, unknown = parser.parse_known_args()
    
    # Assume binary is at ./src/test/fuzz/fuzz relative to CWD or script
    binary_path = "./src/test/fuzz/fuzz"
    if not os.path.exists(binary_path):
        # Try relative to script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        binary_path = os.path.join(script_dir, "src", "test", "fuzz", "fuzz")
        if not os.path.exists(binary_path):
             print(f"Error: Fuzz binary not found at {binary_path}")
             sys.exit(1)
        
    print(f"Running standalone fuzzer wrapper for target: {args.target}")
    print(f"Duration: {args.max_total_time}s, Jobs: {args.jobs}")
    print(f"Binary: {binary_path}")
    
    end_time = time.time() + args.max_total_time
    
    pool = multiprocessing.Pool(processes=args.jobs)
    worker_args = [(binary_path, args.target, end_time) for _ in range(args.jobs)]
    
    try:
        results = pool.map(worker, worker_args)
        pool.close()
        pool.join()
        
        if all(results):
            print("Fuzzing completed successfully (no crashes found).")
        else:
            print("Fuzzing found crashes!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nFuzzing interrupted.")
        pool.terminate()
        pool.join()

if __name__ == "__main__":
    main()
