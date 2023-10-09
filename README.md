# Allowance Module
A Safe Module which aids in execution of token transfer via the Safe contract.

# How to setup the project
- Install [Foundry](https://book.getfoundry.sh/getting-started/installation) (If not installed already)
- Install OpenZeppelin and Safe Contracts: `forge install` (Module specified in git submodules files).
- To test: `forge test` (To see logs use -v and other combinations to see logs at different levels).

# Assumptions
- ERC20 tokens only (not compatible with ERC1155)

# Independent decision & reason
- Initially thought to make a `balance` variable to store the `amount` of tokens which can be transferred from the safe for the `beneficiary`. But then didn't moved forward with this idea, as a beneficiary could be scammed providing them with a signature with higher amount, and later on, the safe owner not depositing enough tokens to initiate the withdraw by the beneficiary.
- Initially thought to make safe and token to be changed later on, but decided against it, as the requirement mentioned to work for specific safe and token.

# Improvements which can be made
- To make it compatible with any safe and any token, instead of compatible to only a particular safe & token pair.
- Signature to include the caller of the function instead of beneficiary, which allows the caller to transfer token to any beneficiary instead of just a pre defined one (gives more flexibility). Example: Alice wants to give Bob the tokens, and uses this module. Currently Bob has to receive the token, and then transfer it to any particular person. Bob can for sure mention to Alice to make it to say Carol. But let's say he changes his mind mid way, he then has to ask again to Alice to create another signature, which is tedious. If the beneficiary can be passed by Bob, he can send it to anyone he requires, even after the signature is created.
- Tests could be improved to use `expectRevert(...)` to be specific to a particular revert reason, rather than using `fail` keyword for reverting cases.

# References & Tools Used
- Foundry
- https://docs.safe.global/safe-smart-account/modules
- https://github.com/safe-global/safe-modules
- https://github.com/colinnielsen/safe-tools
