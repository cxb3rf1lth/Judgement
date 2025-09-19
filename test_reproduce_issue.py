#!/usr/bin/env python3
"""
Test script to reproduce the ValueError issue
"""
from rich.prompt import Prompt

def test_current_behavior():
    """Test the current behavior that causes the error"""
    print("Testing current behavior...")
    try:
        # This should fail when user enters "y"
        max_threads = int(Prompt.ask("Max concurrent threads", default="10"))
        print(f"Success: max_threads = {max_threads}")
    except ValueError as e:
        print(f"Error: {e}")
        return False
    return True

def test_fixed_behavior():
    """Test improved behavior with validation"""
    print("\nTesting improved behavior...")
    
    while True:
        try:
            user_input = Prompt.ask("Max concurrent threads", default="10")
            max_threads = int(user_input)
            if max_threads < 1:
                print("Please enter a positive number.")
                continue
            if max_threads > 200:
                print("Maximum allowed threads is 200. Using 200.")
                max_threads = 200
            print(f"Success: max_threads = {max_threads}")
            return True
        except ValueError:
            print(f"Invalid input '{user_input}'. Please enter a valid number.")
            continue

if __name__ == "__main__":
    print("=== Testing Integer Input Validation ===")
    test_current_behavior()
    test_fixed_behavior()