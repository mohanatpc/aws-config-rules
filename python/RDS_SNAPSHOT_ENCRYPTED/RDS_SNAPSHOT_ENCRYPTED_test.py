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

import unittest
from mock import patch, MagicMock
from rdklib import Evaluation, ComplianceType
import rdklibtest

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

MODULE = __import__('RDS_SNAPSHOT_ENCRYPTED')
RULE = MODULE.RDS_SNAPSHOT_ENCRYPTED()

CLIENT_FACTORY = MagicMock()

# example for mocking S3 API calls
RDS_CLIENT_MOCK = MagicMock()

RULE_PARAMETERS = {'kmsKeyId': 'arn:aws:kms:ap-south-1:653566069331:key/2fae0d44-1951-421d-ba9d-2e2e759b577c'}


def mock_get_client(client_name, *args, **kwargs):
    if client_name == 'rds':
        return RDS_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")

@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    def test_rds_snapshot_encrypted(self):
        configuration = {"configuration": {"encrypted": True}}
        response = RULE.evaluate_change({}, {}, configuration, {})
        resp_expected = [Evaluation(ComplianceType.COMPLIANT)]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected)

    def test_rds_snapshot_not_encrypted(self):
        configuration = {"configuration": {"encrypted": False}}
        response = RULE.evaluate_change({}, {}, configuration, {})
        resp_expected = [Evaluation(ComplianceType.NON_COMPLIANT,
                                    annotation="Encryption is not enabled for this DB snapshot")]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected)

    def test_rds_snapshot_encrypted_kms_key_id_matched(self):
        configuration = {"configuration": {"encrypted": True,
                                           "kmsKeyId": "arn:aws:kms:ap-south-1:653566069331:key/"
                                                       "2fae0d44-1951-421d-ba9d-2e2e759b577c"}}
        response = RULE.evaluate_change({}, {}, configuration, RULE_PARAMETERS)
        resp_expected = [Evaluation(ComplianceType.COMPLIANT)]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected)

    def test_rds_snapshot_encrypted_kms_key_id_not_matched(self):
        configuration = {"configuration": {"encrypted": True,
                                           "kmsKeyId": "arn:aws:kms:ap-south-1:653566069331:key/"
                                                       "2fae0d44-1951-421d-ba9d-2e2e759b588c"}}
        response = RULE.evaluate_change({}, {}, configuration, RULE_PARAMETERS)
        resp_expected = [Evaluation(ComplianceType.NON_COMPLIANT,
                                    annotation="RDS snapshot encrypted KMS key id "
                                               "does not match with configured KMS key id")]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected)
