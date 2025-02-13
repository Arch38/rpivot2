# This library is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library. If not, see <http://www.gnu.org/licenses/> or <http://www.gnu.org/licenses/lgpl.txt>.

import hashlib
import hmac
from ntlm_auth import des


def _lmowfv1(password, lmhash):
    """
    [MS-NLMP] v28.0 2016-07-14

    3.3.1 NTLM v1 Authentication
    Same function as LMOWFv1 in document to create a one way hash of the password. Only
    used in NTLMv1 auth without session security

    @param password: The password of the user we are trying to authenticate with
    @param lmhash: ...
    :return res: A Lan Manager hash of the password supplied
    """

    # fix the password length to 14 bytes
    if lmhash is not None:
        return lmhash.decode('hex')

    password = password.upper()
    lm_pw = password[0:14]

    # do hash
    magic_str = b"KGS!@#$%"  # page 56 in [MS-NLMP v28.0]

    res = b''
    dobj = des.DES(lm_pw[0:7])
    res = res + dobj.encrypt(magic_str)

    dobj = des.DES(lm_pw[7:14])
    res = res + dobj.encrypt(magic_str)
    return res


def _ntowfv1(password, nthash):
    """
    [MS-NLMP] v28.0 2016-07-14

    3.3.1 NTLM v1 Authentication
    Same function as NTOWFv1 in document to create a one way hash of the password. Only
    used in NTLMv1 auth without session security

    @param password: The password of the user we are trying to authenticate with
    @param nthash: ...
    :return digest: An NT hash of the password supplied
    """
    if nthash is not None:
        return nthash.decode('hex')

    digest = hashlib.new('md4', password.encode('utf-16le')).digest()
    return digest


def _ntowfv2(user_name, password, nthash, domain_name):
    """
    [MS-NLMP] v28.0 2016-07-14

    3.3.2 NTLM v2 Authentication
    Same function as NTOWFv2 (and LMOWFv2) in document to create a one way hash of the password.
    This combines some extra security features over the v1 calculations used in NTLMv2 auth.

    @param user_name: The username of the user we are trying to authenticate with
    @param password: The password of the user we are trying to authenticate with
    @param nthash: ...
    @param domain_name: The domain name of the user account we are authenticated with
    @return digest: An NT hash of the parameters supplied
    """
    digest = _ntowfv1(password, nthash)
    digest = hmac.new(digest, (user_name.upper() + domain_name).encode('utf-16le')).digest()

    return digest
