from tarfile import RECORDSIZE
import brownie

def test_vesting_grant_add(accounts, token, Vesting, chain):
  owner = accounts[0]
  owner_balance = token.balanceOf(owner)
  vesting = Vesting.deploy(token,{"from":owner})
  
  recipient = accounts[0]
  duration = 30
  amount = 100
  token.approve(vesting, 10**6, {"from":owner})
  vesting.addGrant(recipient, chain.time(), amount, duration, {"from":owner})

  grants = vesting.getActiveGrants(recipient)
  assert len(grants) == 1
  grant = vesting.tokenGrants(grants[0])
  assert grant[5] == recipient
  assert grant[2] == duration 
  assert grant[1] == amount

