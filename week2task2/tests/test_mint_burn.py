#!/usr/bin/python3
import brownie

def test_mint(accounts, token):
    balance_before = token.balanceOf(accounts[0])
    token.mint(10**18, {'from': accounts[0]})
    balance_after = token.balanceOf(accounts[0])
    assert balance_after - balance_before == 10**18

def test_burn(accounts, token):
    balance_before = token.balanceOf(accounts[0])
    token.burn(10**18, {'from': accounts[0]})
    balance_after = token.balanceOf(accounts[0])
    assert balance_before - balance_after == 10**18