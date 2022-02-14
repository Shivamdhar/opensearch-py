# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.
#
#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.

import sys

from ...exceptions import ImproperlyConfigured

# AWS OpenSearch service name
OPENSEARCH_SERVICE = "es"


def python_version_gte_36():  # type: ignore
    """
    :return: boolean to show if python version running is greater than equal to 3.6 or not
    """
    if sys.hexversion >= 0x03060000:
        return True
    else:
        return False


class Signer:
    """
    A generic signer class that can be extended by cloud providers
    to provide the desired way of authentication.
    """

    def __init__(self):  # type: ignore
        pass

    def sign_request(self):  # type: ignore
        pass


class AwsSignerV4(Signer):
    """
    AwsSignerV4 extends from base class Signer and makes use of
    AWS region and boto session credentials to return the signer.
    """

    def __init__(self, region, session_credentials):  # type: ignore
        self.region = region
        self.session_credentials = session_credentials

    def sign_request(self):  # type: ignore
        """
        :return: SigV4Auth object used as AWS signing mechanism
        """
        if python_version_gte_36():  # type: ignore
            try:
                from botocore.auth import SigV4Auth  # type: ignore

                return SigV4Auth(
                    self.session_credentials, OPENSEARCH_SERVICE, self.region
                )
            except ImportError:
                raise ImproperlyConfigured("Please install botocore to use AwsSigner.")
        else:
            raise ImproperlyConfigured(
                "Please upgrade the python version to 3.6 or above to use AWS Signer."
            )
