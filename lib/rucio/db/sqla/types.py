# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import uuid

import sqlalchemy.types as types
from sqlalchemy.dialects.mysql import BINARY
from sqlalchemy.dialects.oracle import CLOB, RAW
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import operators
from sqlalchemy.types import CHAR, String, TypeDecorator

from rucio.common.exception import InvalidType
from rucio.common.types import InternalAccount, InternalScope


class GUID(TypeDecorator):
    """
    Platform-independent GUID type.

    Uses PostgreSQL's UUID type,
    uses Oracle's RAW type,
    uses MySQL's BINARY type,
    otherwise uses CHAR(32), storing as stringified hex values.

    """

    impl = CHAR

    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(UUID())
        elif dialect.name == 'oracle':
            return dialect.type_descriptor(RAW(16))
        elif dialect.name == 'mysql':
            return dialect.type_descriptor(BINARY(16))
        else:
            return dialect.type_descriptor(CHAR(32))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value).lower()
        elif dialect.name == 'oracle':
            return uuid.UUID(value).bytes
        elif dialect.name == 'mysql':
            return uuid.UUID(value).bytes
        else:
            if not isinstance(value, uuid.UUID):
                return "%.32x" % uuid.UUID(value).int
            else:
                # hexstring
                return "%.32x" % value.int

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'oracle':
            return str(value if isinstance(value, uuid.UUID) else uuid.UUID(bytes=value)).replace('-', '').lower()
        elif dialect.name == 'mysql':
            return str(value if isinstance(value, uuid.UUID) else uuid.UUID(bytes=value)).replace('-', '').lower()
        else:
            return str(value if isinstance(value, uuid.UUID) else uuid.UUID(value)).replace('-', '').lower()


class BooleanString(TypeDecorator):
    """
    Encode True/False/String in a VARCHAR type for all databases.
    """

    impl = String

    cache_ok = True

    def load_dialect_imp(self, dialect):
        return dialect.type_descriptor(String(255))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        # handle booleans always as lowercase string 'true'/'false'
        if isinstance(value, bool):
            if value:
                return 'true'
            return 'false'
        elif isinstance(value, str):
            if value.lower() == 'true':
                return 'true'
            elif value.lower() == 'false':
                return 'false'

        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value

        if value.lower() == 'true':
            return True
        elif value.lower() == 'false':
            return False
        else:
            return value


class JSON(TypeDecorator):
    """
    Platform independent json type

    JSONB for postgres , JSON for the rest
    """

    impl = types.JSON

    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSONB())
        elif dialect.name == 'mysql':
            return dialect.type_descriptor(types.JSON())
        elif dialect.name == 'oracle':
            return dialect.type_descriptor(CLOB())
        else:
            return dialect.type_descriptor(String())


class InternalAccountString(TypeDecorator):
    """
    Encode InternalAccount in a VARCHAR type for all databases.
    """

    impl = String

    cache_ok = True

    def load_dialect_imp(self, dialect):
        return dialect.type_descriptor(String(255))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        if isinstance(value, str):
            raise InvalidType('Cannot insert to db. Expected InternalAccount, got string type.')
        else:
            return value.internal

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return InternalAccount(value, from_external=False)

    def coerce_compared_value(self, op, value):
        if op in (operators.like_op, operators.notlike_op):
            return String()
        else:
            return self


class InternalScopeString(TypeDecorator):
    """
    Encode InternalScope in a VARCHAR type for all databases.
    """

    impl = String

    cache_ok = True

    def load_dialect_imp(self, dialect):
        return dialect.type_descriptor(String(255))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        if isinstance(value, str):
            raise InvalidType('Cannot insert to db. Expected InternalScope, got string type.')
        else:
            return value.internal

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return InternalScope(value, from_external=False)

    def coerce_compared_value(self, op, value):
        if op in (operators.like_op, operators.notlike_op):
            return String()
        else:
            return self
