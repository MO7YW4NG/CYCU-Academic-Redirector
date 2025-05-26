// 十六進制字符
const HEX_CHARS = "0123456789abcdef";

/**
 * 將32位數字轉換為十六進制字串（低位元組在前）
 */
function numberToHex(num) {
    let str = "";
    for (let j = 0; j <= 3; j++) {
        str += HEX_CHARS.charAt((num >> (j * 8 + 4)) & 0x0F) +
               HEX_CHARS.charAt((num >> (j * 8)) & 0x0F);
    }
    return str;
}

/**
 * 將字串轉換為16字塊序列，並添加填充位元和長度
 */
function stringToBlocks(str) {
    const nblk = ((str.length + 8) >> 6) + 1;
    const blks = new Array(nblk * 16);
    
    // 初始化所有塊為0
    for (let i = 0; i < nblk * 16; i++) {
        blks[i] = 0;
    }
    
    // 將字串字符轉換為塊
    for (let i = 0; i < str.length; i++) {
        blks[i >> 2] |= str.charCodeAt(i) << ((i % 4) * 8);
    }
    
    // 添加填充位元
    blks[str.length >> 2] |= 0x80 << ((str.length % 4) * 8);
    
    // 添加原始長度（位元）
    blks[nblk * 16 - 2] = str.length * 8;
    
    return blks;
}

/**
 * 32位整數加法，處理溢出
 */
function safeAdd(x, y) {
    const lsw = (x & 0xFFFF) + (y & 0xFFFF);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
}

/**
 * 32位數字左旋轉
 */
function rotateLeft(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
}

/**
 * MD5 基本運算函數
 */
function cmn(q, a, b, x, s, t) {
    return safeAdd(rotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
}

function ff(a, b, c, d, x, s, t) {
    return cmn((b & c) | ((~b) & d), a, b, x, s, t);
}

function gg(a, b, c, d, x, s, t) {
    return cmn((b & d) | (c & (~d)), a, b, x, s, t);
}

function hh(a, b, c, d, x, s, t) {
    return cmn(b ^ c ^ d, a, b, x, s, t);
}

function ii(a, b, c, d, x, s, t) {
    return cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/**
 * 計算字串的MD5雜湊值
 * @param {string} str - 要計算雜湊值的字串
 * @returns {string} 32字符的十六進制MD5雜湊值
 */
function calcMD5(str) {
    const x = stringToBlocks(str);
    let a = 1732584193;
    let b = -271733879;
    let c = -1732584194;
    let d = 271733878;

    for (let i = 0; i < x.length; i += 16) {
        const olda = a, oldb = b, oldc = c, oldd = d;

        // Round 1
        a = ff(a, b, c, d, x[i + 0], 7, -680876936);
        d = ff(d, a, b, c, x[i + 1], 12, -389564586);
        c = ff(c, d, a, b, x[i + 2], 17, 606105819);
        b = ff(b, c, d, a, x[i + 3], 22, -1044525330);
        a = ff(a, b, c, d, x[i + 4], 7, -176418897);
        d = ff(d, a, b, c, x[i + 5], 12, 1200080426);
        c = ff(c, d, a, b, x[i + 6], 17, -1473231341);
        b = ff(b, c, d, a, x[i + 7], 22, -45705983);
        a = ff(a, b, c, d, x[i + 8], 7, 1770035416);
        d = ff(d, a, b, c, x[i + 9], 12, -1958414417);
        c = ff(c, d, a, b, x[i + 10], 17, -42063);
        b = ff(b, c, d, a, x[i + 11], 22, -1990404162);
        a = ff(a, b, c, d, x[i + 12], 7, 1804603682);
        d = ff(d, a, b, c, x[i + 13], 12, -40341101);
        c = ff(c, d, a, b, x[i + 14], 17, -1502002290);
        b = ff(b, c, d, a, x[i + 15], 22, 1236535329);

        // Round 2
        a = gg(a, b, c, d, x[i + 1], 5, -165796510);
        d = gg(d, a, b, c, x[i + 6], 9, -1069501632);
        c = gg(c, d, a, b, x[i + 11], 14, 643717713);
        b = gg(b, c, d, a, x[i + 0], 20, -373897302);
        a = gg(a, b, c, d, x[i + 5], 5, -701558691);
        d = gg(d, a, b, c, x[i + 10], 9, 38016083);
        c = gg(c, d, a, b, x[i + 15], 14, -660478335);
        b = gg(b, c, d, a, x[i + 4], 20, -405537848);
        a = gg(a, b, c, d, x[i + 9], 5, 568446438);
        d = gg(d, a, b, c, x[i + 14], 9, -1019803690);
        c = gg(c, d, a, b, x[i + 3], 14, -187363961);
        b = gg(b, c, d, a, x[i + 8], 20, 1163531501);
        a = gg(a, b, c, d, x[i + 13], 5, -1444681467);
        d = gg(d, a, b, c, x[i + 2], 9, -51403784);
        c = gg(c, d, a, b, x[i + 7], 14, 1735328473);
        b = gg(b, c, d, a, x[i + 12], 20, -1926607734);

        // Round 3
        a = hh(a, b, c, d, x[i + 5], 4, -378558);
        d = hh(d, a, b, c, x[i + 8], 11, -2022574463);
        c = hh(c, d, a, b, x[i + 11], 16, 1839030562);
        b = hh(b, c, d, a, x[i + 14], 23, -35309556);
        a = hh(a, b, c, d, x[i + 1], 4, -1530992060);
        d = hh(d, a, b, c, x[i + 4], 11, 1272893353);
        c = hh(c, d, a, b, x[i + 7], 16, -155497632);
        b = hh(b, c, d, a, x[i + 10], 23, -1094730640);
        a = hh(a, b, c, d, x[i + 13], 4, 681279174);
        d = hh(d, a, b, c, x[i + 0], 11, -358537222);
        c = hh(c, d, a, b, x[i + 3], 16, -722521979);
        b = hh(b, c, d, a, x[i + 6], 23, 76029189);
        a = hh(a, b, c, d, x[i + 9], 4, -640364487);
        d = hh(d, a, b, c, x[i + 12], 11, -421815835);
        c = hh(c, d, a, b, x[i + 15], 16, 530742520);
        b = hh(b, c, d, a, x[i + 2], 23, -995338651);

        // Round 4
        a = ii(a, b, c, d, x[i + 0], 6, -198630844);
        d = ii(d, a, b, c, x[i + 7], 10, 1126891415);
        c = ii(c, d, a, b, x[i + 14], 15, -1416354905);
        b = ii(b, c, d, a, x[i + 5], 21, -57434055);
        a = ii(a, b, c, d, x[i + 12], 6, 1700485571);
        d = ii(d, a, b, c, x[i + 3], 10, -1894986606);
        c = ii(c, d, a, b, x[i + 10], 15, -1051523);
        b = ii(b, c, d, a, x[i + 1], 21, -2054922799);
        a = ii(a, b, c, d, x[i + 8], 6, 1873313359);
        d = ii(d, a, b, c, x[i + 15], 10, -30611744);
        c = ii(c, d, a, b, x[i + 6], 15, -1560198380);
        b = ii(b, c, d, a, x[i + 13], 21, 1309151649);
        a = ii(a, b, c, d, x[i + 4], 6, -145523070);
        d = ii(d, a, b, c, x[i + 11], 10, -1120210379);
        c = ii(c, d, a, b, x[i + 2], 15, 718787259);
        b = ii(b, c, d, a, x[i + 9], 21, -343485551);

        a = safeAdd(a, olda);
        b = safeAdd(b, oldb);
        c = safeAdd(c, oldc);
        d = safeAdd(d, oldd);
    }
    
    return numberToHex(a) + numberToHex(b) + numberToHex(c) + numberToHex(d);
}
function strencode(string, token) {
    // 如果沒有提供 token，使用預設值
    if (!token) {
        // 如果在瀏覽器環境中，嘗試從 DOM 獲取 token
        if (typeof document !== 'undefined' && typeof $ !== 'undefined') {
            token = $("#token").val() || "4e51d956901213a919078fa977b3793f";
        } else {
            token = "4e51d956901213a919078fa977b3793f";
        }
    }
    
    // 使用 MD5 生成密鑰
    var key = calcMD5("280cyculib" + token);
    
    // 第一次 base64 編碼
    string = btoa(string);
    
    // XOR 加密
    var len = key.length;
    var code = '';
    for (var i = 0; i < string.length; i++) {
        var k = i % len;
        code += String.fromCharCode(string.charCodeAt(i) ^ key.charCodeAt(k));
    }
    
    // 第二次 base64 編碼並返回
    return btoa(code);
}