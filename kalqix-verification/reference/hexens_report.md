---
firm: "Hexens"
firm_id: "hexens"
project: "for KalqiX"
audit_year: 2026
audit_date_min: "2026-01-13"
audit_date_max: "2026-01-13"
audit_date_basis: "report_issue"
audit_type: "infrastructure"
languages: ["unknown"]
chains: ["unknown"]
original_url: "https://github.com/Hexens/Smart-Contract-Review-Public-Reports/blob/84e78849628ca0d9114b66bf886ae11d9e0f8a50/kalqix-dec-25%28Final%29.pdf"
report_id: "290eb5622147fdfbfcf5cad4a02c90043a339108da9979bbf0040cdc14e5aad9"
engagement_id: "engagement:294df33b1e619505439e9c33892dd9779b57428bdf137e2da81a223a3ae03861"
severity_counts: {"critical": 0, "high": 0, "medium": 3, "low": 3, "info": 3, "gas": 0, "unknown": 0}
finding_records: 9
---

## "ERC20 bridge does not reject sent ETH"

finding_uid: "finding:13246b6309cd1cde5d7f16abd7283bb66e115acb1879e0fff12152a9cd6ae956"
finding_id: "KALQ1-6"
title: "ERC20 bridge does not reject sent ETH"
severity: "info"
status: "fixed"
vuln_group: "input_validation"
vuln_leaf: "input_validation.bounds"
engagement_id: "engagement:294df33b1e619505439e9c33892dd9779b57428bdf137e2da81a223a3ae03861"
body_text_status: "present"
text_withheld: null
body_truncated: false
body_text_redactions: "{}"
text_attribution: null
text_license: null
text_license_url: null
text_source_url: null

<!-- body_text:start -->
KALQ1-6 | ERC20 bridge does not reject sent ETH                                                     Fixed


Severity:                  Informational               Probability:   Very likely   Impact:   Informational


Path:
contracts/KalqiXBridge.sol:bridgeAsset#L213-L292


Description:
The bridgeAsset function allows for bridging of both ETH and any ERC20. The function is
marked as payable and therefore accepts msg.value.

If the token parameter is not _NATIVE_TOKEN_ADDRESS however, and the user accidentally
sends ETH, the ETH will become permanently locked in the contract, as there is no check on
whether msg.value is empty when bridging an ERC20 asset.

  // Line 213–266 in KalqiXBridge.sol

  function bridgeAsset(

      address destinationAddress,

      uint256 amount,

      address token,

      bytes calldata permitData

  ) external payable override ifNotEmergencyState nonReentrant {

      // ...

      if (token == _NATIVE_TOKEN_ADDRESS) {

           if (msg.value != amount) {

                revert ValueDoesNotMatchMsgValue();

           }

      } else {

           if (permitData.length != 0) {

                _permit(token, amount, permitData);

           }

           IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

      }

      // ...

  }


Remediation:
Consider adding a check such as require(msg.value == 0) when depositing ERC20 tokens.

<!-- body_text:end -->

## "Forced exit leads to accounting desync"

finding_uid: "finding:2f7d3ed63e807de567788359e52e72e82d6cf51810aa80e0691816a33356a390"
finding_id: "KALQ1-4"
title: "Forced exit leads to accounting desync"
severity: "medium"
status: "fixed"
vuln_group: "bridge"
vuln_leaf: "bridge.asset_conservation"
engagement_id: "engagement:294df33b1e619505439e9c33892dd9779b57428bdf137e2da81a223a3ae03861"
body_text_status: "present"
text_withheld: null
body_truncated: false
body_text_redactions: "{}"
text_attribution: null
text_license: null
text_license_url: null
text_source_url: null

<!-- body_text:start -->
KALQ1-4 | Forced exit leads to accounting desync                                                 Fixed


   Severity:             Medium              Probability:        Likely             Impact:   Medium



Path:
contracts/KalqiXBridge.sol#L516-L583


Description:
The forcedExit function allows users to withdraw funds during emergency state by providing a
Jellyfish Merkle Tree (JMT) proof of their balances. However, the function transfers tokens to
users without decrementing the tokenVsDeposits mapping, which tracks the total amount of
deposits for each token.This creates an accounting mismatch. When users call forcedExit during
an emergency, tokens are sent out and the contract balance decreases, but tokenVsDeposits
remains unchanged. The bridge then believes more funds are available than actually exist.

Later, when users try to withdraw via claimAsset with valid merkle proofs, the function passes
merkle verification and attempts to transfer tokens. If the contract balance is insufficient due to
the earlier forced exits, the transfer fails and the transaction reverts, causing a denial of service
for legitimate users.The issue is that forcedExit transfers tokens without decrementing
tokenVsDeposits, while claimAsset correctly decrements it. This inconsistency breaks the
accounting system. After forced exits occur, the bridge's internal accounting shows funds that are
no longer in the contract, leading to failed withdrawals for users with valid proofs.


     function forcedExit(

        UserBalances.Balances calldata balances,

        JellyfishMerkleTreeVerifier.Proof calldata proof,

        address receiver

     ) external ifEmergencyState nonReentrant {




        BridgeStorage.Layout storage s = BridgeStorage.layout();




        if(receiver == address(0)) {

              revert InvalidAsset();

        }




        bytes32 valueHash = UserBalances.encodeBalances(balances);

        bytes32 keyHash = sha256(abi.encodePacked(msg.sender));




        JellyfishMerkleTreeVerifier.Leaf memory leaf = JellyfishMerkleTreeVerifier.Leaf({

              keyHash: keyHash,

          valueHash: valueHash

  });



  bytes32 accountRoot = IKalqiX(s.kalqiX).accountRoot();

  bool verification = JellyfishMerkleTreeVerifier.verifyProof(accountRoot, leaf, proof);



  if (!verification) {

      revert FailedToVerifyJMTProof();

  }



  for(uint256 i = 0; i < balances.items.length; i++) {

     UserBalances.Balance memory balance = balances.items[i];

     BridgeStorage.AssetConfig memory assetConfig = s.assetConfigs[balance.assetId];



          if (s.forcedExitClaimed[keyHash][balance.assetId]) {

              continue;

          }



          if (!assetConfig.emergencyWithdrawalAllowed) {

              continue;

          }



          s.forcedExitClaimed[keyHash][balance.assetId] = true;



          if (assetConfig.asset == _NATIVE_TOKEN_ADDRESS) {

       

            /* solhint-disable avoid-low-level-calls */

            (bool success, ) = receiver.call{value: balance.amount}(

                new bytes(0)

            );

            if (!success) {

                s.forcedExitClaimed[keyHash][balance.assetId] = false;

                emit FailedToTransferEther();

            }

 

          } else {

             

               bool ok = SafeERC20.trySafeTransfer(IERC20(assetConfig.asset), receiver, balance.amount);

               if (!ok) {

                   s.forcedExitClaimed[keyHash][balance.assetId] = false;

                   emit TokenTransferFailed();

               }

          }

        }






        emit ForcedExit(



              msg.sender,



              receiver



        );



    }




Remediation:


Update tokenVsDeposits in forcedExit after each successful transfer to keep accounting in sync

with contract balances.

<!-- body_text:end -->

## "Priority exit Requests can cause temporary DoS"

finding_uid: "finding:48732827b0066d3034a674827eb3c2fb7b1dd2a23ef4981470114ceba7643510"
finding_id: "KALQ1-3"
title: "Priority exit Requests can cause temporary DoS"
severity: "medium"
status: "fixed"
vuln_group: "dos"
vuln_leaf: "dos.resource_limits"
engagement_id: "engagement:294df33b1e619505439e9c33892dd9779b57428bdf137e2da81a223a3ae03861"
body_text_status: "present"
text_withheld: null
body_truncated: false
body_text_redactions: "{}"
text_attribution: null
text_license: null
text_license_url: null
text_source_url: null

<!-- body_text:start -->
KALQ1-3 | Priority exit Requests can cause temporary DoS                                 Fixed

   Severity:               Medium             Probability:    Likely   Impact:       Medium


Path:
contracts/KalqiXBridge.sol:requestPriorityExit#L153-L204

Description:
The requestPriorityExit function adds a new entry to priorityExitTree without verifying the
caller’s actual token balance. Because the function does not validate that the caller actually owns
or has deposited the specified amount, an attacker can repeatedly submit priority exit requests
with arbitrary values.

If the attacker fills the priorityExitTree up to the maxUnprocessedPriorityExits limit, legitimate
users will be temporarily unable to call requestPriorityExit, as no additional entries can be
accepted.

   function requestPriorityExit(

      address token,

        uint256 amount

   ) external override ifNotEmergencyState nonReentrant {

        // ...




        if (amount == 0) {

              revert ZeroAmount();

        }



        if (amount < assetConfig.minWithdrawal) {

              revert LessThanAllowedMinWithdrawalAmount();

        }



        s.priorityExitTree._addLeaf(...); 

        // ...

   }

Remediation:



We recommend to consider requiring a minimum ETH fee makes it economically expensive to


submit a large number of priority exit requests, mitigating DoS attacks against priorityExitTree. It


could also be possible to allow users to re-claim this ETH if the exit request was processed


successfully (this can already be implemented easily using the count variable).

<!-- body_text:end -->

## "Funds could be permanently lost when cancelling deposits"

finding_uid: "finding:6721014667bc5d60921969b07b28813ab8d7ae0538e99a297a9a17653007fb7e"
finding_id: "KALQ1-5"
title: "Funds could be permanently lost when cancelling deposits"
severity: "low"
status: "acknowledged"
vuln_group: "access_control"
vuln_leaf: "access_control.missing_authorization"
engagement_id: "engagement:294df33b1e619505439e9c33892dd9779b57428bdf137e2da81a223a3ae03861"
body_text_status: "present"
text_withheld: null
body_truncated: false
body_text_redactions: "{}"
text_attribution: null
text_license: null
text_license_url: null
text_source_url: null

<!-- body_text:start -->
KALQ1-5 | Funds could be permanently lost when                                              Acknowledged
cancelling deposits

   Severity:              Low                   Probability:          Rare      Impact:       Medium


Path:
contracts/KalqiXBridge.sol:cancelDeposit#L467-L507

Description:
Whenever a user uses the bridgeAsset function to bridge some assets, it stores the destination
address, token, and amount in s.deposits.

   s.deposits[uint32(s.depositTree.leafCount)] = BridgeStorage.Deposit({

     to: destinationAddress,

     token: token,

     amount: receivedAmount

   });


However, cancelDeposit does not appear to enforce any authorization checks (e.g., verifying that
msg.sender is the original depositor / requester). As a result, any user can call
cancelDeposit(depositNumber) and cancel other users’ deposit requests, effectively triggering
the refund flow for deposits they do not own.

Additionally, the deposit.to address corresponds to an L2 destination address. If that address is a
contract address or a different EOA, then it may not exist on L1 (or may not be able to receive
funds correctly on L1). Therefore, when cancelDeposit executes, the funds may be transferred to
a non-existent or non-payable address on L1, causing the funds to be permanently lost.

   function cancelDeposit(uint32 depositNumber) external ifEmergencyState nonReentrant {

    BridgeStorage.Layout storage s = BridgeStorage.layout();

    ...

    BridgeStorage.Deposit memory deposit = s.deposits[depositNumber];



    // Transfer funds

    if (deposit.token == _NATIVE_TOKEN_ADDRESS) {

        /* solhint-disable avoid-low-level-calls */

        (bool success, ) = deposit.to.call{value: deposit.amount}(

          new bytes(0)

          );

          if (!success) {

              revert EtherTransferFailed();

          }

       } else {

          IERC20(deposit.token).safeTransfer(

              deposit.to,

              deposit.amount

          );

       }

   }

Remediation:
Consider refunding the assets to the original msg.sender of the bridgeAsset function.
Commentary from the client:
“The bridgeAsset function allows anyone to deposit funds on anyone's behalf but destination
address is the one which is the ultimate beneficiary. So in our opinion in case of cancelDeposit
the original beneficiary of the bridge asset function should get the funds back. For ex- if some
product is using intent based system to deposit on behalf of their users then if we allow funds to
be sent back to the msg.sender then it may get sent to the wrong address.”

<!-- body_text:end -->

## "Deposit cancellation leads to accounting desync"

finding_uid: "finding:6c66d5b6425dd3daeb5e40becdb857ed70d1a15721ee3af6c5f8c62cd34ad536"
finding_id: "KALQ1-1"
title: "Deposit cancellation leads to accounting desync"
severity: "medium"
status: "fixed"
vuln_group: "logic_accounting"
vuln_leaf: "logic_accounting.balance_shares"
engagement_id: "engagement:294df33b1e619505439e9c33892dd9779b57428bdf137e2da81a223a3ae03861"
body_text_status: "present"
text_withheld: null
body_truncated: false
body_text_redactions: "{}"
text_attribution: null
text_license: null
text_license_url: null
text_source_url: null

<!-- body_text:start -->
KALQ1-1 | Deposit cancellation leads to accounting desync                                             Fixed


   Severity:          Medium                  Probability:    Unlikely           Impact:         Medium



Path:
contracts/KalqiXBridge.sol:cancelDeposit#L467-L507


Description:
When the cancelDeposit function is executed, it should decrease the value of
s.tokenVsDeposits[deposit.token] to reflect the cancelled deposit. However, there is no logic
that reduces this value.

As a result, the internal accounting for deposited tokens remains higher than the actual balance
after a cancellation.

Because tokenVsDeposits is not decremented during cancelDeposit, calling bridgeAsset after
emergency mode is disabled and after a deposit cancellation has happened, it may incorrectly
trigger the BreachingMaxDepositAllowed revert. This happens even when the real deposited
amount is within the allowed limit.


  if (assetConfig.maxDeposit != 0 &&

      (s.tokenVsDeposits[token] + receivedAmount > assetConfig.maxDeposit)) {

      revert BreachingMaxDepositAllowed();

  }



  /**

  * @notice this method allows non proven deposits to be cancelled if emergencey has been declared

  * @param depositNumber Deposit number to be cancelled

  */

  function cancelDeposit(uint32 depositNumber) external ifEmergencyState nonReentrant {

    BridgeStorage.Layout storage s = BridgeStorage.layout();



      if (s.lastVerifiedDepositNumber >= depositNumber) {

          revert InvalidDespositNumberForCancellation();

      }

        if (s.cancelledDeposits[depositNumber]) {

                 revert DespositHasAlreadyBeenCancelled();

        }

    

        s.cancelledDeposits[depositNumber] = true;




        BridgeStorage.Deposit memory deposit = s.deposits[depositNumber];

    

        // Transfer funds

        if (deposit.token == _NATIVE_TOKEN_ADDRESS) {

                

                 /* solhint-disable avoid-low-level-calls */

                 (bool success, ) = deposit.to.call{value: deposit.amount}(

                       new bytes(0)

                 );

                 if (!success) {

                       revert EtherTransferFailed();

                 }

    

        } else {

                 IERC20(deposit.token).safeTransfer(

                       deposit.to,

                       deposit.amount

                 );

        }




        emit DepositCancelled(

                 depositNumber,

                 deposit.token,

                 deposit.to,

                 deposit.amount

        );




   }



Remediation:
Consider adding the following line at the end of the function:


   tokenVsDeposits[token] -= deposit.amount

<!-- body_text:end -->

## "Read-only reentrancy of tokenVsDeposits"

finding_uid: "finding:7a033d61742b3ba2edbb549f8556bf00029e2ff560bf7146a62dd5b523953d72"
finding_id: "KALQ1-7"
title: "Read-only reentrancy of tokenVsDeposits"
severity: "info"
status: "fixed"
vuln_group: "reentrancy"
vuln_leaf: "reentrancy.readonly"
engagement_id: "engagement:294df33b1e619505439e9c33892dd9779b57428bdf137e2da81a223a3ae03861"
body_text_status: "present"
text_withheld: null
body_truncated: false
body_text_redactions: "{}"
text_attribution: null
text_license: null
text_license_url: null
text_source_url: null

<!-- body_text:start -->
KALQ1-7 | Read-only reentrancy of tokenVsDeposits                                               Fixed




Severity:          Informational             Probability:     Very likely    Impact:      Informational




Path:


contracts/KalqiXBridge.sol:claimAsset#L309-L386




Description:


In the function claimAsset, a user can proof an exit and the contract will send the assets to the

destination address.



The transfer of native asset / ETH happens on line 364 using a .call internal function and no gas

limit. Afterwards, there is a state update:




   s.tokenVsDeposits[tokenAddress] = s.tokenVsDeposits[tokenAddress] - amountWithdrawn;




This means that during the callback of the ETH transfer, there is an invalid intermediate state of

the contract as tokenVsDeposits is still higher than it should be.



This value can be queried using the external view function tokenVsDeposits(address token) of

the contract, leading to potential read-only reentrancy for any contract or protocol that depends

on this value.




     function claimAsset(



        bytes32[_TREE_DEPTH] calldata smtProofLocalExitRoot,



        bytes32[_TREE_DEPTH] calldata smtProofRollupExitRoot,



        uint256 globalIndex,



        address tokenAddress,



        uint32 destinationNetwork,



        address destinationAddress,



        uint256 amount



     ) external override nonReentrant {






        BridgeStorage.Layout storage s = BridgeStorage.layout();






        uint256 amountWithdrawn = amount;






        // Destination network must be this networkID



        if (destinationNetwork != s.networkID) {



            revert DestinationNetworkInvalid();

  }



 



  if (destinationAddress == address(0)) {



           revert InvalidAddress();



  }



 



  uint32 assetId = s.assetVsAssetId[tokenAddress];



  BridgeStorage.AssetConfig memory assetConfig = s.assetConfigs[assetId];






  if (assetConfig.minWithdrawal > amount) {



           revert LessThanAllowedMinWithdrawAmount();



  }



 



  // Verify leaf exist and it does not have been claimed



  _verifyLeaf(



           s.networkID,



           smtProofLocalExitRoot,



           smtProofRollupExitRoot,



           globalIndex,



           SMTHelper.getLeafValueForExitTree(



                 tokenAddress,



                 destinationNetwork,



                 destinationAddress,



                 amount



           )



  );






  uint256 fees = 0;



  if (assetConfig.withdrawalFee != 0) {



           fees = (amount * assetConfig.withdrawalFee) / 10000;



           amount = amount - fees;



           s.tokenVsFeesAccrued[tokenAddress] += fees;



  }






  // Transfer funds



  if (tokenAddress == _NATIVE_TOKEN_ADDRESS) {



          



           /* solhint-disable avoid-low-level-calls */



           (bool success, ) = destinationAddress.call{value: amount}(



                 new bytes(0)



           );



           if (!success) {



                 revert EtherTransferFailed();

                     }

              

               } else {

                     IERC20(tokenAddress).safeTransfer(

                           destinationAddress,

                           amount

                     );

               }




               s.tokenVsDeposits[tokenAddress] = s.tokenVsDeposits[tokenAddress] - amountWithdrawn;

               emit ClaimEvent(

                     globalIndex,

                     tokenAddress,

                     destinationAddress,

                     amount

               );

     

         }



Remediation:
We recommend to follow the CEI (checks, effects, interations) pattern by first decreasing the
value of s.tokenVsDeposits[tokenAddress] and only then perform the ETH/ERC20 transfer.

<!-- body_text:end -->

## "Minimum withdrawal change could lock users' exits"

finding_uid: "finding:c548ba1dea7a135e6bb8ce14236a630eb169ccf4b6c8075d211980a2b2e46fb2"
finding_id: "KALQ1-8"
title: "Minimum withdrawal change could lock users' exits"
severity: "low"
status: "acknowledged"
vuln_group: "bridge"
vuln_leaf: "bridge.message_lifecycle"
engagement_id: "engagement:294df33b1e619505439e9c33892dd9779b57428bdf137e2da81a223a3ae03861"
body_text_status: "present"
text_withheld: null
body_truncated: false
body_text_redactions: "{}"
text_attribution: null
text_license: null
text_license_url: null
text_source_url: null

<!-- body_text:start -->
KALQ1-8 | Minimum withdrawal change could lock users'                                                      Acknowledged




exits




   Severity:                     Low                       Probability:                   Rare   Impact:     Medium




Path:



contracts/KalqiXBridge.sol:claimAsset#L309-L386




Description:



In the function claimAsset, there is a check of the amount against the currently set minimum


withdrawal amount:




   if (assetConfig.minWithdrawal > amount) {




       revert LessThanAllowedMinWithdrawAmount();




   }




This amount is presumably also checked when creating the exit, but by also checking it against


the currently set one at the moment of claiming, it could potentially lock users from claiming their


exit if the assetConfig.minWithdrawal was previously increased.




For example, if the minimum withdrawal amount is set to 0.1 ETH and a user initiates an exit of that


amount. Before the user claims, the configuration changes to a minimum withdrawal amount of


0.2 ETH and now the user is permanently unable to claim their exit due to the check.




       function claimAsset(

          bytes32[_TREE_DEPTH] calldata smtProofLocalExitRoot,

          bytes32[_TREE_DEPTH] calldata smtProofRollupExitRoot,

          uint256 globalIndex,

          address tokenAddress,

          uint32 destinationNetwork,

          address destinationAddress,

          uint256 amount

       ) external override nonReentrant {



           B   ridge   S   torage.La   yout   storage = B
                                                      s     ridge   S   torage.   layout ;


                                                                                         ()




           uint256         amountWithdrawn       =   amount;

  // Destination network must be this networkID



  if (destinationNetwork != s.networkID) {



           revert DestinationNetworkInvalid();



  }



 



  if (destinationAddress == address(0)) {



           revert InvalidAddress();



  }



 



  uint32 assetId = s.assetVsAssetId[tokenAddress];



  BridgeStorage.AssetConfig memory assetConfig = s.assetConfigs[assetId];






  if (assetConfig.minWithdrawal > amount) {



           revert LessThanAllowedMinWithdrawAmount();



  }



 



  // Verify leaf exist and it does not have been claimed



  _verifyLeaf(



           s.networkID,



           smtProofLocalExitRoot,



           smtProofRollupExitRoot,



           globalIndex,



           SMTHelper.getLeafValueForExitTree(



                tokenAddress,



                destinationNetwork,



                destinationAddress,



                amount



           )



  );






  uint256 fees = 0;



  if (assetConfig.withdrawalFee != 0) {



           fees = (amount * assetConfig.withdrawalFee) / 10000;



           amount = amount - fees;



           s.tokenVsFeesAccrued[tokenAddress] += fees;



  }






  // Transfer funds



  if (tokenAddress == _NATIVE_TOKEN_ADDRESS) {



          



           /* solhint-disable avoid-low-level-calls */



           (bool success, ) = destinationAddress.call{value: amount}(



                new bytes(0)

                     );

                     if (!success) {

                           revert EtherTransferFailed();

                     }

              

               } else {

                     IERC20(tokenAddress).safeTransfer(

                           destinationAddress,

                           amount

                     );

               }




               s.tokenVsDeposits[tokenAddress] = s.tokenVsDeposits[tokenAddress] - amountWithdrawn;

               emit ClaimEvent(

                     globalIndex,

                     tokenAddress,

                     destinationAddress,

                     amount

               );

     

         }



Remediation:
We recommend to either only perform the minimum withdrawal amount check during creation of
the exit, such that future changes would not impact the exit, or to restrict configuration changes
to only allow a decrease of the minimum withdrawal amount.

<!-- body_text:end -->

## "Redundant priority exit root query if count is zero"

finding_uid: "finding:c7f0a8709ffd47d9eb6a0fc6ee370a317a98312f4eeea6d03e795c65f87c4ad9"
finding_id: "KALQ1-9"
title: "Redundant priority exit root query if count is zero"
severity: "info"
status: "fixed"
vuln_group: "gas"
vuln_leaf: "gas.execution"
engagement_id: "engagement:294df33b1e619505439e9c33892dd9779b57428bdf137e2da81a223a3ae03861"
body_text_status: "present"
text_withheld: null
body_truncated: false
body_text_redactions: "{}"
text_attribution: null
text_license: null
text_license_url: null
text_source_url: null

<!-- body_text:start -->
KALQ1-9 | Redundant priority exit root query if count is zero                                                                                   Fixed


Severity:                       Informational                              Probability:                       Likely            Impact:   Informational


Path:
contracts/KalqiX.sol:verifyBlock#L125-L204


Description:
The function verifyBlock allows the trusted batcher role submit block proofs and update the
global exit root.

In the function, it uses the parameter _processedPriorityExitCount to fetch the corresponding
priorityExitVsRoot from the Kalqix Bridge on line 144:

    bytes32 priorityExitRoot = IKalqiXBridge(s.bridge).priorityExitVsRoot(_processedPriorityExitCount);



H owe er, afterwards it immediatel o erwrites this alue to a constant if the count alue is equal
            v                                                          y    v                            v                                v


to ero.

    z



These two lines could be merged into a single if else, where the quer call to the Kalqix Bridge      -                          y


can be made conditional and therefore sa ing gas when the count is                         v                                    0.




        function verifyBlock(




            uint256 _startBlock,




            uint256 _endBlock,




            bytes32 _globalExitRoot,




            bytes32 _accountRoot,




            uint32 _depositCount,




            uint32 _processedPriorityExitCount,




            bytes calldata proof




        )   external ifNotEmergencyState onlyRole _TRUSTED_BATCHER_ROLE          (                                     )   {




            Kalq XSi       tor ge.
                                a         La   yout   storage         s=         i
                                                                           Kalq XS         tor ge.
                                                                                                 a   layout   ()
                                                                                                               ;






            if   (_st rt oc =
                       a   Bl       k !    latestBlockNumber                ()   + 1   )   {




                 revert InvalidStartBlock                () ;




            }




            if   (_st rt oc
                       a   Bl       k >   _end oc )
                                                  Bl    k        {




                 revert StartBlockGreaterThanEndBlock                                  ()   ;




            }


bytes32 depositRoot = IKalqiXBridge(s.bridge).depositVsRoot(_depositCount);



bytes32 priorityExitRoot = IKalqiXBridge(s.bridge).priorityExitVsRoot(_processedPriorityExitCount);






if(_processedPriorityExitCount == 0) {



      priorityExitRoot = _GENESIS_PRIORITY_EXIT_ROOT;



}



if (IKalqiXBridge(s.bridge).priorityExitCount() > _processedPriorityExitCount) {



      (, , , uint256 requestedAt) = IKalqiXBridge(s.bridge).priorityExits(_processedPriorityExitCount + 1);






      if (block.timestamp > (uint64(requestedAt) + MAX_PRIORITY_EXIT_PROCESSING_TIME)) {



            revert UnprocessedPriorityExitsWithTimeLimitReached();



      }



}






if (s.totalVerifiedProofs == 0) {



      IKalqiXVerifier(s.verifier).verify(



            _startBlock,



            _endBlock,



            _globalExitRoot,



            _accountRoot,



            depositRoot,



            priorityExitRoot,



            _GENESIS_GLOBAL_EXIT_ROOT,



            _GENESIS_ACCOUNT_ROOT,



            proof



      );



} else {



      IKalqiXVerifier(s.verifier).verify(



            _startBlock,



            _endBlock,



            _globalExitRoot,



            _accountRoot,



            depositRoot,



            priorityExitRoot,



            s.outputRoots[s.totalVerifiedProofs].globalExitRoot,



            s.outputRoots[s.totalVerifiedProofs].accountRoot,



            proof



      );



}



s.totalVerifiedProofs = s.totalVerifiedProofs + 1;






IKalqiXBridge(s.bridge).updateLastVerifiedDepositNumber(_depositCount);



IKalqiXBridge(s.bridge).updateProcessedPriorityExits(_processedPriorityExitCount);

          emit BlockVerified(

                 _startBlock,

                 _endBlock,

                 s.totalVerifiedProofs,

                 block.timestamp

          );




          s.outputRoots[s.totalVerifiedProofs] = KalqiXStorage.OutputRoots(

                 {

                        startBlock: _startBlock,

                        endBlock: _endBlock,

                        timestamp: uint128(block.timestamp),

                        globalExitRoot: _globalExitRoot,

                        accountRoot: _accountRoot,

                        depositRoot: depositRoot,

                        priorityExitRoot: priorityExitRoot

                 });

      }



Remediation:
Change the logic as follows:


  bytes32 priorityExitRoot;

  if (_processedPriorityExitCount == 0) {

      priorityExitRoot = _GENESIS_PRIORITY_EXIT_ROOT;

  } else {

      priorityExitRoot = IKalqiXBridge(s.bridge).priorityExitVsRoot(_processedPriorityExitCount);

  }

x

<!-- body_text:end -->

## "Missing token validation in requestPriorityExit"

finding_uid: "finding:f36b8942cac296788874a70ea85624abaeb4441abcce01d5f418bdfa076710a9"
finding_id: "KALQ1-10"
title: "Missing token validation in requestPriorityExit"
severity: "low"
status: "fixed"
vuln_group: "input_validation"
vuln_leaf: "input_validation.address_parameter"
engagement_id: "engagement:294df33b1e619505439e9c33892dd9779b57428bdf137e2da81a223a3ae03861"
body_text_status: "present"
text_withheld: null
body_truncated: false
body_text_redactions: "{}"
text_attribution: null
text_license: null
text_license_url: null
text_source_url: null

<!-- body_text:start -->
KALQ1-10 | Missing token validation in requestPriorityExit                                                    Fixed


   Severity:              Low                 Probability:         Rare                Impact:           Medium



Path:
contracts/KalqiXBridge.sol:requestPriorityExit#L153-L204


Description:
The requestPriorityExit function retrieves asset configuration using assetVsAssetId[token],
which returns 0 (the default value) for unregistered tokens. The function then accesses
assetConfigs[0] and validates against its configuration, but critically fails to verify that the
provided token matches assetConfig.asset.

If assetConfigs[0] is configured with emergencyWithdrawalAllowed = true (which occurs when
an admin registers an asset at index 0), an attacker can call requestPriorityExit with any arbitrary
unregistered token address and pass all validation checks. This allows filling the priority exit
queue with invalid requests, causing denial of service for legitimate users attempting to request
priority exits.


   /**

      * This function allows users to request priority exit. Each priority exit request needs to be processed by the

      * roll up within the MAX_PRIORITY_EXIT_PROCESSING_TIME otherwise KalqiX contract will stop
   accepting new blocks

      * @param token Address of the token

      * @param amount Amount of token

      */

     function requestPriorityExit(

          address token,

          uint256 amount

     ) external override ifNotEmergencyState nonReentrant {




          BridgeStorage.Layout storage s = BridgeStorage.layout();




          uint32 assetId = s.assetVsAssetId[token];



          BridgeStorage.AssetConfig memory assetConfig = s.assetConfigs[assetId];




          if (amount == 0) {

              revert ZeroAmount();

          }

         if (!assetConfig.emergencyWithdrawalAllowed) {

             revert PriorityExitNotSupportedForToken();

         }



         if (amount < assetConfig.minWithdrawal) {

             revert LessThanAllowedMinWithdrawalAmount();

         }



         s.priorityExitTree._addLeaf(

              SMTHelper.getLeafValueForExitTree(

                 token,

                 s.networkID,

                 msg.sender,

                 amount

              )

         );



         s.priorityExitVsRoot[uint32(s.priorityExitTree.leafCount)] = s.priorityExitTree.getRoot();

         s.priorityExits[uint32(s.priorityExitTree.leafCount)] = BridgeStorage.PriorityExit({

               user: msg.sender,

               token: token,

               amount: amount,

               requestedAt: block.timestamp

         });



         if ((s.priorityExitTree.leafCount - s.processedPriorityExits) > s.maxUnprocessedPriorityExits) {

             revert MaxUnprocessedPriorityExitsReached();

         }



         emit PriorityExitRequest(

              uint32(s.priorityExitTree.leafCount),

              token,

              msg.sender,

              amount

         );



     }


Remediation:
Add explicit token validation (assetConfig.asset == token) before processing the priority exit
request.

<!-- body_text:end -->

