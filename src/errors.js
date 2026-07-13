/***************************************************************************
 * subtlepq: DOMException helpers with WebCrypto-mandated error names
 *
 * (c) 2026 VESvault Corp
 * SPDX-License-Identifier: Apache-2.0
 ***************************************************************************/

const err = (name, message) => new DOMException(message, name);

export const notSupported = (m) => err("NotSupportedError", m);
export const invalidAccess = (m) => err("InvalidAccessError", m);
export const dataError = (m) => err("DataError", m);
export const opError = (m) => err("OperationError", m);
export const syntaxError = (m) => err("SyntaxError", m);
