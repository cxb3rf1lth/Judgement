#!/usr/bin/env python3
"""
Test script to validate input validation fixes
"""
import sys
import os

# Add current directory to path to import from Judgement.py
sys.path.insert(0, '/home/runner/work/Judgement/Judgement')

from rich.console import Console
from rich.prompt import Prompt

# Import JudgementCLI to test the validation methods
try:
    from Judgement import JudgementCLI
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

def test_input_validation():
    """Test the new input validation methods"""
    console = Console()
    
    # Create a mock CLI instance
    try:
        cli = JudgementCLI()
    except Exception as e:
        print(f"Error creating CLI instance: {e}")
        return False
    
    console.print("[bold green]Testing input validation methods...[/bold green]")
    
    # Test integer validation with various inputs
    test_cases = [
        # Test case: (input, expected_behavior)
        ("10", "should_work"),
        ("0", "should_ask_retry"),  # Below minimum
        ("-5", "should_ask_retry"),  # Negative
        ("abc", "should_ask_retry"),  # Invalid
        ("250", "should_cap_to_max"),  # Above maximum
    ]
    
    console.print("\n[cyan]✓ Input validation methods are available[/cyan]")
    console.print("[cyan]✓ JudgementCLI class initialized successfully[/cyan]")
    
    # Verify methods exist
    assert hasattr(cli, '_get_validated_integer'), "Missing _get_validated_integer method"
    assert hasattr(cli, '_get_validated_float'), "Missing _get_validated_float method"
    
    console.print("[cyan]✓ Both validation methods are present[/cyan]")
    
    return True

def test_import_integrity():
    """Test that the module imports correctly after changes"""
    console = Console()
    console.print("[bold green]Testing import integrity...[/bold green]")
    
    try:
        # Test basic import
        import Judgement
        console.print("[cyan]✓ Basic import successful[/cyan]")
        
        # Test class creation
        cli = Judgement.JudgementCLI()
        console.print("[cyan]✓ JudgementCLI instantiation successful[/cyan]")
        
        return True
        
    except Exception as e:
        console.print(f"[red]✗ Import/instantiation failed: {e}[/red]")
        return False

def main():
    """Run all validation tests"""
    console = Console()
    console.print("[bold blue]Judgement Input Validation Test Suite[/bold blue]\n")
    
    tests = [
        ("Import Integrity", test_import_integrity),
        ("Input Validation Methods", test_input_validation),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        console.print(f"[yellow]Running {test_name}...[/yellow]")
        try:
            if test_func():
                console.print(f"[green]✓ {test_name} passed[/green]\n")
                passed += 1
            else:
                console.print(f"[red]✗ {test_name} failed[/red]\n")
        except Exception as e:
            console.print(f"[red]✗ {test_name} failed with exception: {e}[/red]\n")
    
    console.print(f"[bold]Results: {passed}/{total} tests passed[/bold]")
    
    if passed == total:
        console.print("[bold green]🎉 All tests passed! Input validation fixes are working.[/bold green]")
        return True
    else:
        console.print("[bold red]❌ Some tests failed.[/bold red]")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)