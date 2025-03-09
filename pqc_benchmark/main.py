import argparse
import os
import matplotlib.pyplot as plt
from tabulate import tabulate
from .algorithms import get_all_algorithms, generate_keys, benchmark_signature
import random
import string

def generate_test_data(size):
    """Generate test data of specified size"""
    return os.urandom(size)

def generate_test_message(size):
    """Generate a random string message of specified size"""
    chars = string.ascii_letters + string.digits + string.punctuation
    message = ''.join(random.choices(chars, k=size))
    return message

def display_comparison_table():
    algorithms = get_all_algorithms()
    
    # Prepare table data with correct units
    table_data = []
    for algo in algorithms:
        table_data.append([
            algo.name,
            f"{algo.pub_key_size_bytes} bytes",  # Key sizes in bytes
            f"{algo.priv_key_size_bytes} bytes",  # Key sizes in bytes
            f"{algo.signature_size_min_bytes}-{algo.signature_size_max_bytes} bytes" if algo.signature_size_min_bytes != algo.signature_size_max_bytes else f"{algo.signature_size_max_bytes} bytes",  # Show range for variable sizes
            algo.type
        ])
    
    # Display table with unit labels
    print("Cryptographic Algorithm Comparison")
    print(tabulate(
        table_data,
        headers=["Algorithm", "Pub Key Size (bytes)", "Priv Key Size (bytes)", "Signature Size (bytes)", "Type"],
        tablefmt="pretty"
    ))

def generate_graphs(results, algorithms):
    """Generate and save performance graphs with dot plots and log scale"""
    message_sizes = [0, 1024, 10*1024, 100*1024, 1024*1024]
    size_labels = ['0B', '1KB', '10KB', '100KB', '1MB']
    dot_sizes = [50, 100, 150, 200, 250]  # Different sizes for each message size
    
    # Create figure with two subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 14))
    
    # Get algorithm names for x-axis
    algo_names = [algo.name for algo in algorithms]
    x_pos = range(len(algo_names))
    
    # Plot signing times with log scale
    for i, size in enumerate(message_sizes):
        sign_times = [results[algo.name][size]['sign_time']*1000 for algo in algorithms]
        ax1.scatter(x_pos, sign_times, s=dot_sizes[i], label=size_labels[i], alpha=0.7)
    
    ax1.set_title('Signing Time by Algorithm')
    ax1.set_xlabel('Algorithm')
    ax1.set_ylabel('Sign Time (ms)')
    ax1.set_yscale('log')
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels(algo_names, rotation=45, ha='right')
    ax1.grid(True, which="both", ls="-")
    ax1.legend(title="Message Size")
    
    # Plot verification times with log scale
    for i, size in enumerate(message_sizes):
        verify_times = [results[algo.name][size]['verify_time']*1000 for algo in algorithms]
        ax2.scatter(x_pos, verify_times, s=dot_sizes[i], label=size_labels[i], alpha=0.7)
    
    ax2.set_title('Verification Time by Algorithm')
    ax2.set_xlabel('Algorithm')
    ax2.set_ylabel('Verify Time (ms)')
    ax2.set_yscale('log')
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(algo_names, rotation=45, ha='right')
    ax2.grid(True, which="both", ls="-")
    ax2.legend(title="Message Size")
    
    # Save and show plots
    plt.tight_layout()
    plt.savefig('pqc_benchmark_results.png')
    print("\nGraphs saved as pqc_benchmark_results.png")

def display_performance_table(iterations):
    algorithms = get_all_algorithms()
    message_sizes = [0, 1024, 10*1024, 100*1024, 1024*1024]
    
    # Generate keys once for all tests
    print("\nGenerating keys...")
    keys = {}
    keygen_times = {}
    for algo in algorithms:
        print(f"Generating keys for {algo.name}...", end=" ", flush=True)
        keys[algo.name] = generate_keys(algo)
        keygen_times[algo.name] = keys[algo.name]['keygen_time']
        print(f"done ({keygen_times[algo.name]*1000:.2f} ms)")
    
    print(f"\nPerformance Benchmarking (times in milliseconds, iterations={iterations})")
    
    # Display key generation times
    print("\nKey Generation Times")
    keygen_table = []
    for algo in algorithms:
        keygen_table.append([
            algo.name,
            f"{keygen_times[algo.name]*1000:.2f}"
        ])
    print(tabulate(
        keygen_table,
        headers=["Algorithm", "KeyGen Time (ms)"],
        tablefmt="pretty"
    ))
    
    # Collect results for graphs
    results = {algo.name: {} for algo in algorithms}
    
    # Run benchmarks for each message size
    for size in message_sizes:
        print(f"\nMessage Size: {size} bytes")
        
        table_data = []
        for algo in algorithms:
            print(f"Testing {algo.name}...", end=" ", flush=True)
            
            # Use string messages for XMSS algorithms, bytes for others
            if algo.botan_alg == "XMSS":
                message = generate_test_message(size)
            else:
                message = generate_test_data(size)
                
            results[algo.name][size] = benchmark_signature(algo, keys[algo.name], message, iterations)
            print("done")
            
            table_data.append([
                algo.name,
                f"{results[algo.name][size]['sign_time']*1000:.2f}",
                f"{results[algo.name][size]['verify_time']*1000:.2f}"
            ])
        
        print(tabulate(
            table_data,
            headers=["Algorithm", "Sign Time (ms)", "Verify Time (ms)"],
            tablefmt="pretty"
        ))
    
    # Generate graphs
    generate_graphs(results, algorithms)

def main():
    """Main entry point for the benchmarking tool"""
    parser = argparse.ArgumentParser(description="PQC Algorithm Benchmarking Tool")
    parser.add_argument("-n", "--iterations", type=int, default=10,
                      help="Number of iterations to run for each benchmark (default: 10)")
    
    args = parser.parse_args()
    
    display_comparison_table()
    display_performance_table(args.iterations)

if __name__ == "__main__":
    main()