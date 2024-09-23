#!/usr/bin/env python3
# ***************************************************************************
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# SPDX-FileCopyrightText: Copyright (c) 2020 SoftAtHome
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials provided
# with the distribution.
#
# Subject to the terms and conditions of this license, each
# copyright holder and contributor hereby grants to those receiving
# rights under this license a perpetual, worldwide, non-exclusive,
# no-charge, royalty-free, irrevocable (except for failure to
# satisfy the conditions of this license) patent license to make,
# have made, use, offer to sell, sell, import, and otherwise
# transfer this software, where such license applies only to those
# patent claims, already acquired or hereafter acquired, licensable
# by such copyright holder or contributor that are necessarily
# infringed by:
#
# (a) their Contribution(s) (the licensed copyrights of copyright
# holders and non-copyrightable additions of contributors, in
# source or binary form) alone; or
#
# (b) combination of their Contribution(s) with the work of
# authorship to which such Contribution(s) was added by such
# copyright holder or contributor, if, at the time the Contribution
# is added, such addition causes such combination to be necessarily
# infringed. The patent license shall not apply to any other
# combinations which include the Contribution.
#
# Except as expressly stated above, no rights or licenses from any
# copyright holder or contributor is granted under this license,
# whether expressly, by implication, estoppel or otherwise.
#
# DISCLAIMER
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# **************************************************************************/

import base64
import os
import re
import struct
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetricPadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import fdt

_DEFAULT_DTB_VERSION = 17


class BadInputException(Exception):
    """
    Global exception raised for any error detected in user-formatted input
    """


class Env:
    """
    Environment parser class. Use an instance to parse, then access environment variables.
    """
    # pylint: disable=too-few-public-methods

    class _ValueParser:

        def __init__(self, value):
            self.value = value
            self._parse()

        def _parse(self):
            pass

    class _ValueParserNumber(_ValueParser):

        def _parse(self):
            self.value = int(self.value)

    class _ValueParserString(_ValueParser):

        def _parse(self):
            pass

    class _ValueParserBytes(_ValueParser):

        def _parse(self):
            self.value = bytes(self.value, 'ascii')

    class _ValueParserFile(_ValueParser):

        def _parse(self):
            with open(self.value, 'rb') as valueFile:
                self.value = valueFile.read()

    class _ParamParser:

        def __init__(self, param, valueParser):
            self._param = 'GENPP_' + param.upper()
            self._valueParser = valueParser
            self.value = None
            self._parse()

        def _parse(self):
            pass

    class _SingleParamParser(_ParamParser):

        def _parse(self):
            if self._param in os.environ:
                self.value = self._valueParser(os.environ[self._param]).value

    class _MultipleParamParser(_ParamParser):

        def _parse(self):
            regex = re.compile(self._param + r'_\d+$')
            self.value = {int(key.split('_')[-1]) : self._valueParser(value).value
                          for key, value in os.environ.items() if regex.match(key)}
            if self.value == {}:
                self.value = None

    def __init__(self, preinit=None):
        if preinit is not None:
            self._values = preinit
            return
        self._map = {
            'dtb_version': (self._SingleParamParser, self._ValueParserNumber),
            'pubkey': (self._MultipleParamParser, self._ValueParserFile),
            'privkey': (self._MultipleParamParser, self._ValueParserFile),
            'privkey_password': (self._MultipleParamParser, self._ValueParserBytes),
            'signature_node_name': (self._MultipleParamParser, self._ValueParserString),
            'signing_algo': (self._MultipleParamParser, self._ValueParserString),
            'symmetric_key': (self._MultipleParamParser, self._ValueParserFile),
            'symmetric_iv': (self._MultipleParamParser, self._ValueParserFile),
            'key_name': (self._MultipleParamParser, self._ValueParserString)
        }
        self._values = {paramName : paramParsing[0](paramName, paramParsing[1]).value
                        for paramName, paramParsing in self._map.items()}

    def get(self, paramName: str, index=None, default=-1):
        """
        Getter for environment variable parameter.

        :param str paramName: parameter key name. should be part of the map in the __init__
        :param int index: index used in case of a multiple parameter (cipher keys for instance)
        :param default: value to be returned instead of raising error if the parameter is not found.
        """
        if paramName in self._values and self._values[paramName] is not None:
            if not isinstance(self._values[paramName], dict):
                return self._values[paramName]
            if index in self._values[paramName]:
                return self._values[paramName][index]
        if default != -1:
            return default
        paramFullName = 'GENPP_' + (
            paramName if index is None else paramName + '_' + str(index)).upper()
        raise BadInputException('Could not get environment variable [' +
                                paramFullName + '], needed for build.')


class NodeEncryptor:
    """
    Encryptor utility for a fdt.Node instance.
    Each instance is bound to a fdt.Node instance, and may cipher it.
    """
    # pylint: disable=too-many-instance-attributes
    # pylint: disable=too-few-public-methods

    _ALGO_LIST = {
        'aes': {
            'algo': algorithms.AES,
            'modes': {
                'cbc': modes.CBC
            }
        }
    }

    def __init__(self, node: fdt.Node, env: Env):
        self._env = env
        self._node = node
        self._value = None
        self._cipherNode = self._node.get_subnode('cipher')
        assert self._cipherNode, 'Node should contain a "cipher" node here.'
        self._checkParameters()
        self._parse()

    def _checkParameters(self):
        if not self._cipherNode.exist_property('key_index'):
            raise BadInputException('No "key_index" property in cipher of node ' + self._node.name)
        if not self._cipherNode.exist_property('algo'):
            raise BadInputException('No "algo" property in cipher of node ' + self._node.name)
        if not self._cipherNode.exist_property('mode'):
            raise BadInputException('No "mode" property in cipher of node ' + self._node.name)
        algo = self._cipherNode.get_property('algo').value
        mode = self._cipherNode.get_property('mode').value
        if algo not in self._ALGO_LIST:
            raise BadInputException('Cipher algorithm not supported: ' + algo)
        if mode not in self._ALGO_LIST[algo]['modes']:
            raise BadInputException('Cipher mode not supported: ' + mode + ' with algo ' + algo)

    def _parse(self):
        self._keyIndex = self._cipherNode.get_property('key_index').value
        if NODEPATH == '/RIP_DATA':
            self._keyName = self._env.get('key_name', self._keyIndex)
        self._value = self._node.get_property('value').rawdata()
        self._algo = self._cipherNode.get_property('algo').value
        self._mode = self._cipherNode.get_property('mode').value
        self._key = self._env.get('symmetric_key', self._keyIndex)
        self._iv = self._env.get('symmetric_iv', self._keyIndex)

    def _padd(self):
        padder = padding.PKCS7(len(self._iv) * 8).padder()
        self._value = padder.update(bytes(self._value)) + padder.finalize()

    def _cipher(self):
        encryptionCipher = Cipher(
            self._ALGO_LIST[self._algo]['algo'](self._key),
            self._ALGO_LIST[self._algo]['modes'][self._mode](self._iv),
            backend=default_backend())
        encryptor = encryptionCipher.encryptor()
        self._value = encryptor.update(self._value) + encryptor.finalize()

    def _updateNode(self):
        self._node.remove_property('to_cipher')
        self._node.remove_subnode('cipher')
        cipherDescription = self._algo + '-' + str(len(self._key) * 8) + '-' + self._mode
        self._node.remove_property('value')
        self._node.set_property('type', 'raw')
        self._node.append(fdt.PropBytes('value', data=base64.b64encode(self._value)))
        cipherNode = fdt.Node('cipher')
        self._node.append(cipherNode)
        cipherNode.append(fdt.PropWords('key_index', self._keyIndex))
        if NODEPATH == '/RIP_DATA':
            cipherNode.append(fdt.PropStrings('key_name', self._keyName))
        cipherNode.append(fdt.PropStrings('format', cipherDescription + '-base64'))

    def cipher(self):
        """
        Run the ciphering routine on the node: cipher the value, remove ciphering informations, and
        tag the node as ciphered.
        """
        self._padd()
        self._cipher()
        self._updateNode()


class DTBSigner:
    """
    Signing utility for a fdt.FDT instance.
    Each instance is bound to a fdt.FDT instance, and a key ID.
    A single DTBSigner instance may only sign a fdt for a single private key ID, i.e. only sign the
    field tagged to be signed with this very key ID.
    """
    # pylint: disable=too-many-instance-attributes
    # pylint: disable=too-few-public-methods

    _DEFAULT_ALGO = 'SHA256_PSS'

    _HASH_LIST = {
        'SHA256': hashes.SHA256
    }
    _PADDING_LIST = {
        'PSS': asymmetricPadding.PSS
    }

    def __init__(self, dtb: fdt.FDT, nodes: list, env: Env):
        self._fdt = dtb
        self._env = env
        self._nodes = nodes
        self._value = None
        self._signature = None
        assert self._nodes[0].exist_subnode('signature'), 'Node should have a "signature" here.'
        self._index = self._nodes[0].get_subnode('signature').get_property(SIGNATUREPROPERTY).value
        for node in self._nodes:
            assert (node.exist_subnode('signature') and
                    node.get_subnode('signature').get_property(SIGNATUREPROPERTY).value == self._index), (
                        'Node should have a "sign_index" here.')
        self._checkParameters()
        self._parse()

    def _checkParameters(self):
        algo = self._env.get('signing_algo', self._index, default='SHA256_PSS')
        if algo.split('_')[0] not in self._HASH_LIST:
            raise BadInputException('Signing algorithm ' + algo.split('_')[0] +
                                    ' is not supported.')
        if algo.split('_')[1] not in self._PADDING_LIST:
            raise BadInputException('Padding algorithm ' + algo.split('_')[1] +
                                    ' is not supported.')

    def _parse(self):
        algo = self._env.get('signing_algo', self._index, default='SHA256_PSS')
        self._algo = algo.split('_')[0]
        self._padd = algo.split('_')[1]
        try:
            self._privkey = serialization.load_pem_private_key(
                self._env.get('privkey', self._index),
                self._env.get('privkey_password', self._index, default=None),
                default_backend())
        except TypeError:
            raise BadInputException('Private key ' + str(self._index) +
                                    ' is encrypted, provide password with env variable.')
        self._signNodeName = self._env.get('signature_node_name', self._index)
        if NODEPATH == '/RIP_DATA':
            self._sortNodes()
        self._parsePackedValue()

    def _sign(self):
        signHash = self._HASH_LIST[self._algo]
        self._signature = self._privkey.sign(
            self._value,
            self._PADDING_LIST[self._padd](asymmetricPadding.MGF1(signHash()),
                                           salt_length=signHash.digest_size),
            signHash())

    def _makeSignatureNode(self):
        signAlgo = self._env.get('signing_algo', self._index).lower().replace('_', '-')
        self._fdt.remove_node(self._signNodeName, NODEPATH)
        signNode = fdt.Node(self._signNodeName)
        self._fdt.add_item(signNode, NODEPATH)
        signNode.append(fdt.PropWords('id', self._index))
        signNode.append(fdt.PropStrings('algo', signAlgo))
        signNode.append(fdt.PropStrings('type', 'raw'))
        signNode.append(fdt.PropBytes('value', data=base64.b64encode(self._signature)))

    def _sortNodes(self):
        self._nodes.sort(key=lambda node: node.get_property('id').value)

    def _parsePackedValue(self):

        def getRawValue(node: fdt.Node):
            valueType = node.get_property('type').value
            value = node.get_property('value')
            if valueType == 'string':
                return value.rawdata()[:-1]
            if valueType == 'raw':
                return value.rawdata()
            raise BadInputException('Unknown type field [' + valueType + '] for node ' + node.name)

        self._value = bytearray(b''.join([getRawValue(node) for node in self._nodes]))

    def sign(self):
        """
        Run the signing routine: calculate the signature value, and thus create/update the signature
        node.
        """
        self._sign()
        self._makeSignatureNode()


def cipher(dtb: fdt.FDT, env: Env):
    """
    Run the ciphering routines on all the nodes tagged to be ciphered in dtb.

    :param fdt.FDT dtb: the device tree with nodes to be ciphered
    :param ENV env: environment instance
    """
    cipherNodes = [node for node in dtb.get_node(NODEPATH).nodes
                   if node.exist_property('to_cipher')]
    for node in cipherNodes:
        NodeEncryptor(node, env).cipher()


def sign(dtb: fdt.FDT, env: Env):
    """
    Run the signing routines on the dtb. All signatures to be generated will be generated.

    :param fdt.FDT dtb: the device tree eith nodes to be signed
    :param ENV env: environment instance
    """
    signedNodes = [node for node in dtb.get_node(NODEPATH).nodes
                   if node.exist_subnode('signature')]
    signIds = [node.get_subnode('signature').get_property(SIGNATUREPROPERTY).value for node in signedNodes]
    if len(signedNodes) != len(signIds):
        raise BadInputException('A signed node misses the "sign_index" parameter.')

    for signId in list(set(signIds)):
        nodesWithId = [node for node in signedNodes
                       if node.get_subnode('signature').get_property(SIGNATUREPROPERTY).value == signId]
        DTBSigner(dtb, nodesWithId, env).sign()


def checkDuplicates(dtb: fdt.FDT):
    """
    Check 'id' property duplicates in node of dtb.
    Such duplicates are indeed legal in dtb syntax, but WILL make the dtb impossible to be used by
    middleware, so check it and don't manufacture bricks.

    :param fdt.FDT dtb: device tree to be checked
    """
    ids = [node.get_property('id').value for node in dtb.get_node(NODEPATH).nodes]
    if len(ids) != len(set(ids)):
        raise BadInputException('ID duplicates detected.')

def _fdtStripComments(text):
    text = re.sub(r'(?<=[\^;])\s*//.*?(\r\n?|\n)|/\*.*?\*/', r'\n', text, flags=re.S)
    return text


def _fdtSplitToLines(text):
    lines = []
    mline = str()
    inMlineStr = False
    for line in text.split('\n'):
        line = line.replace('\t', ' ')
        if not inMlineStr:
            line = line.lstrip(' ')
        if line.count('"') % 2 == 1:
            if inMlineStr:
                inMlineStr = False
            else:
                inMlineStr = True
                mline += line + '\n'
                continue
        line = line.rstrip('\0')
        line = line.rstrip(' ')
        if not line or line.startswith('/dts-'):
            continue
        if line.endswith('{') or line.endswith(';'):
            line = line.replace(';', '')
            lines.append(mline + line)
            mline = str()
        elif inMlineStr:
            mline += line + '\n'
        else:
            mline += line + ' '

    return lines

def rewrite_dts(dtb:fdt.FDT, param:str, value:str):
    """
    Add the function to easily modify the mfg data. The mfg data file regeneration is not affected.
    """
    # rewrite the mac address
    if re.search("MAC",param):
        target_arr = re.split(":",value)
        target_str = [int(x,16) for x in target_arr]
        mac_address = bytearray(target_str)
        value = mac_address

    rewriteNode =dtb.get_node(NODEPATH).get_subnode(param)
    rewriteNode.set_property("value",value)

def overrideFdtProp():
    """
    Add convenient properties to fdt module classes:
      - a raw data access for all properties
      - fix an upstream bug: comments regex is used in string props (to be pushed upstream)
      - fix an upstream bug: line breaks in string values are dropped during parsing,
        and space should be added for numeric values on line breaks (to be pushed upstream)
    """
    fdt.PropStrings.rawdata = lambda self: (
        bytearray(''.join([item + '\0' for item in self.data]), 'ascii'))
    fdt.PropWords.rawdata = lambda self: (
        bytearray(b''.join([struct.pack('>I', item) for item in self.data])))
    fdt.PropBytes.rawdata = lambda self: (
        self.data)
    fdt.strip_comments = _fdtStripComments
    fdt.split_to_lines = _fdtSplitToLines


def main(dtss: list, dtbs: list, set_param: str, set_value: str, env: Env):
    """
    Main running function. Does all the stuff.

    :param list dtss: binary data loaded from DTS files.
    :param list dtbs: binary data loaded from DTB files.
    :param ENV env: environment instance
    """
    overrideFdtProp()
    dtbs = [fdt.parse_dts(input) for input in dtss] + [
        fdt.parse_dtb(input) for input in dtbs]

    result = dtbs[0]
    for dtb in dtbs[1:]:
        result.merge(dtb)

    global NODEPATH
    global SIGNATUREPROPERTY
    info = result.info()
    if '/RIP_DATA' in info: # This is used for a SOP build
        NODEPATH = "/RIP_DATA"
        SIGNATUREPROPERTY = "index"
    elif '/MFG_DATA' in info: # This is used for PrplOS
        NODEPATH = "/MFG_DATA"
        SIGNATUREPROPERTY = "key_index"
    else:
        raise BadInputException('Did not detect a valid node name. Please make sure to use RIP_DATA or MFG_DATA as first node.')

    # arcadyan rewrite the dts file
    if set_value != "":
        rewrite_dts(result,set_param,set_value)
    
    cipher(result, env)
    sign(result, env)

    # It is only necessary for SOP builds to check duplicate ids.
    if NODEPATH == '/RIP_DATA':
        checkDuplicates(result)
    return result.to_dtb(env.get('dtb_version', default=_DEFAULT_DTB_VERSION))


def parseArgs(args):
    """
    Simple command line argument parser.
    Consider first argument as the output file name, and all others as dtb and dts file names.
    """
    outputFilename = args[1]
    dtss = []
    dtbs = []
    set_param = ""
    set_value = ""
    for arg in args[2:]:
        if arg[-4:] == '.dts':
            with open(arg, 'r') as argFile:
                dtss.append(argFile.read())
        elif arg[-4:] == '.dtb':
            with open(arg, 'rb') as argFile:
                dtbs.append(argFile.read())
        # else:
        #     print('Unknown file format for [' + arg + ']. Please provide only .dts and .dtb.')
        #     sys.exit(1)

    if args[-2][-4:] != '.dts' and args[-2][-4:] != '.dtb':
        set_param = args[-2]
    if args[-1][-4:] != '.dts' and args[-1][-4:] != '.dtb':
        set_value = args[-1]

    return outputFilename, dtss, dtbs, set_param, set_value


if __name__ == '__main__':
    OUTPUT_FILE_NAME, INPUT_DTS, INPUT_DTB, SET_PARAM, SET_VALUE = parseArgs(sys.argv)
    OUTPUT = main(INPUT_DTS, INPUT_DTB, SET_PARAM, SET_VALUE, Env())
    if OUTPUT_FILE_NAME == '-':
        with os.fdopen(sys.stdout.fileno(), 'wb', closefd=False) as outputFile:
            outputFile.write(OUTPUT)
            outputFile.flush()
    else:
        with open(OUTPUT_FILE_NAME, 'wb') as outputFile:
            outputFile.write(OUTPUT)
