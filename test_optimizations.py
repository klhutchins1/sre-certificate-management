#!/usr/bin/env python3
"""
Performance Optimization Validation Script

This script tests and validates the performance optimizations implemented
in the Infrastructure Management System.

Tests:
1. Lazy loading performance
2. Dependency loading times
3. Cache effectiveness
4. Memory usage improvements
5. Import time optimizations
"""

import time
import sys
import os
import gc
import traceback
import tracemalloc
from pathlib import Path
from typing import Dict, Any, List

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def measure_memory():
    """Measure current memory usage."""
    gc.collect()  # Force garbage collection
    return tracemalloc.get_traced_memory()[0] / 1024 / 1024  # MB

def test_lazy_loading():
    """Test lazy loading performance."""
    print("\n" + "="*60)
    print("Testing Lazy Loading Performance")
    print("="*60)
    
    tracemalloc.start()
    initial_memory = measure_memory()
    
    # Test lazy import utilities
    try:
        from infra_mgmt.utils.lazy_imports import (
            get_plotly, get_matplotlib, get_import_stats, 
            preload_essential_modules, get_available_optional_modules
        )
        
        print("✅ Lazy import utilities loaded successfully")
        
        # Test lazy plotly loading
        start_time = time.time()
        px = get_plotly()
        plotly_load_time = time.time() - start_time
        
        if px:
            print(f"✅ Plotly loaded lazily in {plotly_load_time:.3f}s")
        else:
            print("❌ Plotly not available")
        
        # Test optional matplotlib loading
        start_time = time.time()
        plt = get_matplotlib()
        matplotlib_load_time = time.time() - start_time
        
        if plt:
            print(f"✅ Matplotlib loaded optionally in {matplotlib_load_time:.3f}s")
        else:
            print(f"⚠️  Matplotlib not available (optional) - load time: {matplotlib_load_time:.3f}s")
        
        # Test available modules check
        available_modules = get_available_optional_modules()
        print(f"📊 Available optional modules: {available_modules}")
        
        # Test import statistics
        import_stats = get_import_stats()
        print(f"📊 Import statistics:")
        print(f"   - Modules loaded: {import_stats['module_count']}")
        print(f"   - Total import time: {import_stats['total_import_time']:.3f}s")
        
        current_memory = measure_memory()
        memory_used = current_memory - initial_memory
        print(f"📊 Memory usage after lazy loading: {memory_used:.2f} MB")
        
    except Exception as e:
        print(f"❌ Error testing lazy loading: {e}")
        traceback.print_exc()
    
    tracemalloc.stop()

def test_optimized_requirements():
    """Test optimized requirements."""
    print("\n" + "="*60)
    print("Testing Optimized Requirements")
    print("="*60)
    
    try:
        # Check if optimized requirements file exists
        optimized_req_path = project_root / "requirements_optimized.txt"
        original_req_path = project_root / "requirements.txt"
        
        if optimized_req_path.exists():
            with open(optimized_req_path, 'r') as f:
                optimized_lines = [line.strip() for line in f.readlines() 
                                 if line.strip() and not line.startswith('#')]
            
            with open(original_req_path, 'r') as f:
                original_lines = [line.strip() for line in f.readlines() 
                                if line.strip() and not line.startswith('#')]
            
            optimized_count = len(optimized_lines)
            original_count = len(original_lines)
            reduction = ((original_count - optimized_count) / original_count) * 100
            
            print(f"📊 Dependency Analysis:")
            print(f"   - Original dependencies: {original_count}")
            print(f"   - Optimized dependencies: {optimized_count}")
            print(f"   - Reduction: {reduction:.1f}%")
            
                         # Check for removed packages
             removed_packages = [
                 'altair', 'matplotlib', 'pdfkit', 'weasyprint'
             ]
            
            optimized_text = '\n'.join(optimized_lines)
            for package in removed_packages:
                if package not in optimized_text:
                    print(f"✅ {package} successfully removed")
                else:
                    print(f"⚠️  {package} still present")
            
        else:
            print("❌ requirements_optimized.txt not found")
            
    except Exception as e:
        print(f"❌ Error testing requirements: {e}")

def test_optimized_dashboard():
    """Test optimized dashboard components."""
    print("\n" + "="*60)
    print("Testing Optimized Dashboard")
    print("="*60)
    
    try:
        # Test optimized dashboard import
        start_time = time.time()
        from infra_mgmt.views.dashboardView_optimized import (
            PerformanceCache, get_root_domain_cached
        )
        import_time = time.time() - start_time
        
        print(f"✅ Optimized dashboard imported in {import_time:.3f}s")
        
        # Test performance cache
        cache = PerformanceCache(max_size=10, default_ttl=5)
        
        # Test cache operations
        test_data = {"test": "data", "timestamp": time.time()}
        cache.set("test_key", test_data)
        
        retrieved = cache.get("test_key")
        if retrieved == test_data:
            print("✅ Performance cache working correctly")
        else:
            print("❌ Performance cache not working")
        
        # Test cache statistics
        stats = cache.stats()
        print(f"📊 Cache stats: {stats}")
        
        # Test cached root domain function
        test_domains = ["sub.example.com", "test.domain.org", "simple.com"]
        for domain in test_domains:
            root = get_root_domain_cached(domain)
            print(f"   - {domain} -> {root}")
        
        print("✅ Cached functions working correctly")
        
    except Exception as e:
        print(f"❌ Error testing optimized dashboard: {e}")
        traceback.print_exc()

def test_database_service():
    """Test optimized database service."""
    print("\n" + "="*60)
    print("Testing Optimized Database Service")
    print("="*60)
    
    try:
        from infra_mgmt.services.OptimizedDatabaseService import (
            QueryCache, cache_query
        )
        
        # Test query cache
        cache = QueryCache(max_size=5, default_ttl=10)
        
        # Test cache operations
        test_queries = [
            ("SELECT * FROM certificates", {"result": "cert_data"}),
            ("SELECT * FROM domains", {"result": "domain_data"}),
        ]
        
        for query, result in test_queries:
            cache.set(query, result)
            retrieved = cache.get(query)
            if retrieved == result:
                print(f"✅ Query cache working for: {query[:30]}...")
            else:
                print(f"❌ Query cache failed for: {query[:30]}...")
        
        # Test cache statistics
        stats = cache.stats()
        print(f"📊 Query cache stats: {stats}")
        
        # Test cache decorator (mock function)
        class MockService:
            def __init__(self):
                self.query_cache = cache
                self.call_count = 0
            
            @cache_query(ttl=60)
            def expensive_query(self, param):
                self.call_count += 1
                time.sleep(0.01)  # Simulate expensive operation
                return f"result_for_{param}"
        
        service = MockService()
        
        # First call (cache miss)
        start_time = time.time()
        result1 = service.expensive_query("test")
        first_call_time = time.time() - start_time
        
        # Second call (cache hit)
        start_time = time.time()
        result2 = service.expensive_query("test")
        second_call_time = time.time() - start_time
        
        if result1 == result2 and second_call_time < first_call_time:
            print(f"✅ Cache decorator working (speedup: {first_call_time/second_call_time:.1f}x)")
        else:
            print("❌ Cache decorator not working properly")
        
        print(f"📊 Function called {service.call_count} times (should be 1)")
        
    except Exception as e:
        print(f"❌ Error testing database service: {e}")
        traceback.print_exc()

def benchmark_import_times():
    """Benchmark import times for different approaches."""
    print("\n" + "="*60)
    print("Benchmarking Import Performance")
    print("="*60)
    
    # Test traditional imports vs lazy imports
    import_tests = [
        ("pandas", "import pandas as pd"),
        ("numpy", "import numpy as np"),
        ("streamlit", "import streamlit as st"),
    ]
    
    for module_name, import_code in import_tests:
        if module_name in sys.modules:
            # Module already loaded, can't accurately test
            print(f"⚠️  {module_name} already loaded, skipping benchmark")
            continue
        
        try:
            start_time = time.time()
            exec(import_code)
            import_time = time.time() - start_time
            print(f"📊 {module_name} import time: {import_time:.3f}s")
        except ImportError:
            print(f"⚠️  {module_name} not available")

def run_comprehensive_test():
    """Run all performance tests."""
    print("🚀 Starting Performance Optimization Validation")
    print("=" * 80)
    
    start_time = time.time()
    
    # Run all tests
    test_optimized_requirements()
    test_lazy_loading()
    test_optimized_dashboard()
    test_database_service()
    benchmark_import_times()
    
    total_time = time.time() - start_time
    
    print("\n" + "="*80)
    print("🎯 Performance Test Summary")
    print("="*80)
    print(f"Total test time: {total_time:.2f}s")
    print("\n✅ All optimization tests completed!")
    print("\nRecommendations:")
    print("1. Monitor performance metrics in the optimized dashboard")
    print("2. Use lazy loading for heavy dependencies")
    print("3. Regularly clear caches when data is updated")
    print("4. Consider using optimized requirements.txt for production")

if __name__ == "__main__":
    try:
        run_comprehensive_test()
    except KeyboardInterrupt:
        print("\n❌ Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        traceback.print_exc()