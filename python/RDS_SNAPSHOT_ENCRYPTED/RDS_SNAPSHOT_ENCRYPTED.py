# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.
"""""
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  RDS_SNAPSHOT_ENCRYPTED

Description:
  Check whether AWS RDS Snapshot is encrypted.

Rationale:
  Encrypting a  AWS RDS Snapshot with AWS Key Management Service(KMS) keys ensures protection.

Indicative Severity:
  Medium

Trigger:
  Configuration Change on AWS::RDS::DBSnapshot and AWS::RDS::DBClusterSnapshot

Reports on:
  AWS::RDS::DBSnapshot and AWS::RDS::DBClusterSnapshot

Rule Parameters:
  RDSSnapshotIdentifier
   (Optional) Enter the RDS Snapshot InstanceIdentifier to
   display snapshots are COMPLIANT  (or list of ID separated by ",")

Scenarios:
  Scenario: 2
    Given: AWS RDS Snapshot available and is encrypted with AWS KMS
    Then: Return COMPLIANT
  Scenario: 3
    Given:  AWS RDS Snapshot available and is not encrypted  with AWS KMS
    Then: Return NON_COMPLIANT
same scenarios for DB clusters
"""""

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType


class RdsSnapshotEncrypted(ConfigRule):

    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        response = configuration_item['configuration'].get('encrypted')
        if response is not None and response:
            return [Evaluation(ComplianceType.COMPLIANT)]
        return [Evaluation(ComplianceType.NON_COMPLIANT, annotation="Encryption is not enabled for snapshot")]


def lambda_handler(event, context):
    my_rule = RdsSnapshotEncrypted()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
