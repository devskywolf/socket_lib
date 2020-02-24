var pako = require('pako');
var {AesCtr} = require('./aes-ctr.js');
const CHECK_MARK = '0001';

const SEND_TYPE = {
  ROOM            : 0,    // To send the all users in a room.(channel)
  EXCLUDE_SENDER  : 1,    // To send the all users exclude sender in a room
  ONLY_SERVER     : 2,    // To send only server without sending to other.
  ONLY_SENDER     : 3,    // To send only sender
  ALL             : 4     // To send the all connected users 
}

const DATA_TYPE = {
  JSON            : 0,
  STRING          : 1,
  BYTES           : 2,
  UINT32          : 3,
  UINT64          : 4,
  NONE            : 255
}

const IO_HEADER = {
  check_mark      : { type : DATA_TYPE.STRING, size : 4},
  message_id      : { type : DATA_TYPE.UINT64, size : 8},
  send_type       : { type : DATA_TYPE.BYTE,   size : 1},
  data_type       : { type : DATA_TYPE.BYTE,   size : 1},
  name_size       : { type : DATA_TYPE.BYTE,   size : 1},
  data_size       : { type : DATA_TYPE.UINT64, size : 8},
  chunking_count  : { type : DATA_TYPE.UINT32, size : 4},
  chunking_number : { type : DATA_TYPE.UINT32, size : 4},
  chunking_size   : { type : DATA_TYPE.UINT32, size : 4},
  crc_code        : { type : DATA_TYPE.UINT32, size : 3}
}
  
const MAX_CHUNKING_SIZE = 4096;
const HEADER_SIZE = 38;
const MAX_CHUNKING_DATA_SIZE = MAX_CHUNKING_SIZE - HEADER_SIZE;

class IODataBody {
  constructor(dataType = DATA_TYPE.JSON)
  {
    this.dataType = dataType;
    this.dataSize = 0;
    this.data = null;
    this.msgName = '';
    this.msgNameSize = 0;
    
    this.offset = 0;
    this.isInited = false;
    this.isEnded = false;

    this.crc = 0;
  }

  setInitBytes(msgSize, dataSize)
  {
    this.dataSize = dataSize;
    this.msgNameSize = msgSize;
    this.dataBytes = new Uint8Array(this.dataSize);
  }

  addDataFromBytes(dataBytes)
  {
    if (!this.isInited) {
      this.isInited = true;
      this.isEnded = false;
      this.offset = 0;
    }
    var chunkingBodySize = IOData.getLength(dataBytes);
    
    if (!this.isInited || this.isEnded) {
      return false;
    }

    IOData.ArrayCopy(this.dataBytes, this.offset, dataBytes, 0, chunkingBodySize);
    this.offset += chunkingBodySize;
    return true;
  }
  
  updateDataFromBytes()
  {
    if (this.offset !== this.dataSize) {
      return false;
    }
    this.updateBytesWithDecompression();
    this.dataSize = IOData.getLength(this.dataBytes);
    var msgBytes = new Uint8Array(this.msgNameSize);
    msgBytes = IOData.ArrayCopy(msgBytes, 0, this.dataBytes, 0, this.msgNameSize);
    var bodyBytes = new Uint8Array(this.dataSize - this.msgNameSize);
    bodyBytes = IOData.ArrayCopy(bodyBytes, 0, this.dataBytes, this.msgNameSize, this.dataSize - this.msgNameSize);
    this.msgName = IOData.bytesToData(DATA_TYPE.STRING, msgBytes);
    this.data = IOData.bytesToData(this.dataType, bodyBytes);
    this.isInited = false;
    this.isEnded = true;
  }

  updateBytesWithDecompression()
  {
    this.dataBytes = IOData.getBytesWithDecompression(this.dataBytes);
  }
  
  updateBytesWithCompression()
  {
    this.dataBytes = IOData.getBytesWithCompression(this.dataBytes);
  }

  getDataSize()
  {
    return this.dataSize;
  }

  setData(msgName, bodyData)
  {
    this.msgName = msgName;
    this.data = bodyData;
  }

  generateBytes()
  {
    var msgBytes = IOData.dataToBytes(DATA_TYPE.STRING, this.msgName);
    var msgNameSize = IOData.getLength(msgBytes);
    var bodyBytes = IOData.dataToBytes(this.dataType, this.data);
    var bodySize = IOData.getLength(bodyBytes);
    var dataSize = msgNameSize + bodySize;

    var dataBytes = new Uint8Array(dataSize);
    IOData.ArrayCopy(dataBytes, 0, msgBytes, 0, msgNameSize);
    IOData.ArrayCopy(dataBytes, msgNameSize, bodyBytes, 0, bodySize);
    
    this.dataBytes = dataBytes;
    this.msgNameSize = msgNameSize;
    this.updateBytesWithCompression();
    this.dataSize = IOData.getLength(this.dataBytes);

    return this.dataBytes;
  }

  getChunkingBytes(chunkingNum)
  {
    var offset = MAX_CHUNKING_DATA_SIZE * (chunkingNum - 1);
    var chunkingSize = IOData.getLength(this.dataBytes) - offset;
    if (chunkingSize > MAX_CHUNKING_DATA_SIZE) {
      chunkingSize = MAX_CHUNKING_DATA_SIZE;
    }
    var chunkingBytes = new Uint8Array(chunkingSize);
    IOData.ArrayCopy(chunkingBytes, 0, this.dataBytes, offset, chunkingSize);

    return chunkingBytes;
  }
}

class IODataHeader {
  constructor()
  { }
  setHeader(
    checkMark,
    messageId,
    sendType,
    dataType,
    nameSize,
    dataSize,
    chunkingTotalNum,
    chunkingNum,
    chunkingSize,
    crcCode)
  {
    this.checkMark = checkMark;
    this.messageId = messageId;    
    this.dataType = dataType;
    this.sendType = sendType;
    this.nameSize = nameSize;
    this.dataSize = dataSize;
    this.chunkingTotalNum = chunkingTotalNum;
    this.chunkingNum = chunkingNum;
    this.chunkingSize = chunkingSize;
    this.crcCode = crcCode;
  }

  updateHeaderFromBody(ioBody, chunkingNum)
  {
    var dataSize = ioBody.dataSize;
    var chunkingTotalNum = Math.ceil(dataSize / MAX_CHUNKING_DATA_SIZE);
    
    var curOffset = chunkingNum * MAX_CHUNKING_DATA_SIZE;
    var chunkingSize = dataSize - curOffset;
    if (chunkingSize > MAX_CHUNKING_DATA_SIZE) {
      chunkingSize = MAX_CHUNKING_DATA_SIZE;
    }

    this.dataType = ioBody.dataType;
    this.nameSize = ioBody.msgNameSize;
    this.dataSize = dataSize;
    this.chunkingTotalNum = chunkingTotalNum;
    this.chunkingNum = chunkingNum;
    this.chunkingSize = this.chunkingSize;
    this.crcCode = IOData.getCRCCode(ioBody.dataBytes);
  }
  
  setSendType(sendType)
  {
    this.sendType = sendType;
  }
  
  getSendType()
  {
    return this.sendType;
  }
  
  setDataType(dataType)
  {
    this.dataType = dataType;
  }
  
  getDataType()
  {
    return this.dataType;
  }
  
  getChunkingEndStatus()
  {
    return (this.chunkingNum < this.chunkingTotalNum) ? 0 : 1;
  }
  getChunkingStartStatus()
  {
    return (this.chunkingNum > 1) ? 0 : 1;
  }

  generateBytes()
  {
    var checkMark = this.checkMark;
    var messageId = this.messageId;
    var sendType = this.sendType;
    var dataType = this.dataType;
    var nameSize = this.nameSize;
    var dataSize = this.dataSize;
    var chunkingTotalNum = this.chunkingTotalNum;
    var chunkingNum = this.chunkingNum;
    var chunkingSize = this.chunkingSize;
    var crcCode = this.crcCode;
    
    var headerBytes = new Uint8Array(HEADER_SIZE);
    var offset = 0;
    //checkMark    4 byte
    var checkMarkBytes = IOData.dataToBytes(IO_HEADER.check_mark.type, checkMark);
    IOData.ArrayCopy(headerBytes, 0, checkMarkBytes, 0, IO_HEADER.check_mark.size);
    offset += IO_HEADER.check_mark.size;
    
    //MessageId      8 byte
    var messageIdBytes = IOData.dataToBytes(IO_HEADER.message_id.type, messageId);
    IOData.ArrayCopy(headerBytes, offset, messageIdBytes, 0, IO_HEADER.message_id.size);
    offset += IO_HEADER.message_id.size;
    
    //send type      1byte
    var sendTypeBytes = IOData.dataToBytes(IO_HEADER.send_type.type, sendType);
    IOData.ArrayCopy(headerBytes, offset, sendTypeBytes, 0, IO_HEADER.send_type.size);
    offset += IO_HEADER.send_type.size;

    //data type       1byte
    var dataTypeBytes = IOData.dataToBytes(IO_HEADER.data_type.type, dataType);
    IOData.ArrayCopy(headerBytes, offset, dataTypeBytes, 0, IO_HEADER.data_type.size);
    offset += IO_HEADER.data_type.size;

    //msg name size   1byte
    var nameSizeBytes = IOData.dataToBytes(IO_HEADER.name_size.type, nameSize);
    IOData.ArrayCopy(headerBytes, offset, nameSizeBytes, 0, IO_HEADER.name_size.size);
    offset += IO_HEADER.name_size.size;

    //data size      8 byte
    var dataSizeBytes = IOData.dataToBytes(IO_HEADER.data_size.type, dataSize);
    IOData.ArrayCopy(headerBytes, offset, dataSizeBytes, 0, IO_HEADER.data_size.size);
    offset += IO_HEADER.data_size.size;

    //chunking total count  (4byte)
    var chunkingTotalNumBytes = IOData.dataToBytes(IO_HEADER.chunking_count.type, chunkingTotalNum);
    IOData.ArrayCopy(headerBytes, offset, chunkingTotalNumBytes, 0, IO_HEADER.chunking_count.size);
    offset += IO_HEADER.chunking_count.size;

    //chunking number
    var chunkingNumberBytes = IOData.dataToBytes(IO_HEADER.chunking_number.type, chunkingNum);
    IOData.ArrayCopy(headerBytes, offset, chunkingNumberBytes, 0, IO_HEADER.chunking_number.size);
    offset += IO_HEADER.chunking_number.size;

    var chunkingSizeBytes = IOData.dataToBytes(IO_HEADER.chunking_size.type, chunkingSize);
    IOData.ArrayCopy(headerBytes, offset, chunkingSizeBytes, 0, IO_HEADER.chunking_size.size);
    offset += IO_HEADER.chunking_size.size;

    var crcCodeBytes = IOData.dataToBytes(IO_HEADER.crc_code.type, crcCode);
    IOData.ArrayCopy(headerBytes, offset, crcCodeBytes, 0, IO_HEADER.crc_code.size);
    offset += IO_HEADER.crc_code.size;

    return headerBytes;
  }
  updateFromBytes(headerBytes)
  {
    var offset = 0;
    
    var checkMarkBytes = new Uint8Array(IO_HEADER.check_mark.size);
    IOData.ArrayCopy(checkMarkBytes, 0, headerBytes, offset, IO_HEADER.check_mark.size);
    var checkMark = IOData.bytesToData(IO_HEADER.check_mark.type, checkMarkBytes);
    offset += IO_HEADER.check_mark.size;

    var messageIdBytes = new Uint8Array(IO_HEADER.message_id.size);
    IOData.ArrayCopy(messageIdBytes, 0, headerBytes, offset, IO_HEADER.message_id.size);
    var messageId = IOData.bytesToData(IO_HEADER.message_id.type, messageIdBytes);
    offset += IO_HEADER.message_id.size;

    var sendTypeBytes = new Uint8Array(IO_HEADER.send_type.size);
    IOData.ArrayCopy(sendTypeBytes, 0, headerBytes, offset, IO_HEADER.send_type.size);
    var sendType = IOData.bytesToData(IO_HEADER.send_type.type, sendTypeBytes);
    offset += IO_HEADER.send_type.size;

    var dataTypeBytes = new Uint8Array(IO_HEADER.data_type.size);
    IOData.ArrayCopy(dataTypeBytes, 0, headerBytes, offset, IO_HEADER.data_type.size);
    var dataType = IOData.bytesToData(IO_HEADER.data_type.type, dataTypeBytes);
    offset += IO_HEADER.data_type.size;

    var nameSizeBytes = new Uint8Array(IO_HEADER.name_size.size);
    IOData.ArrayCopy(nameSizeBytes, 0, headerBytes, offset, IO_HEADER.name_size.size);
    var nameSize = IOData.bytesToData(IO_HEADER.name_size.type, nameSizeBytes);
    offset += IO_HEADER.name_size.size;

    var dataSizeBytes = new Uint8Array(IO_HEADER.data_size.size);
    IOData.ArrayCopy(dataSizeBytes, 0, headerBytes, offset, IO_HEADER.data_size.size);
    var dataSize = IOData.bytesToData(IO_HEADER.data_size.type, dataSizeBytes);
    offset += IO_HEADER.data_size.size;

    var chunkingTotalNumBytes = new Uint8Array(IO_HEADER.chunking_count.size);
    IOData.ArrayCopy(chunkingTotalNumBytes, 0, headerBytes, offset, IO_HEADER.chunking_count.size);
    var chunkingTotalNum = IOData.bytesToData(IO_HEADER.chunking_count.type, chunkingTotalNumBytes);
    offset += IO_HEADER.chunking_count.size;

    var chunkingNumBytes = new Uint8Array(IO_HEADER.chunking_number.size);
    IOData.ArrayCopy(chunkingNumBytes, 0, headerBytes, offset, IO_HEADER.chunking_number.size);
    var chunkingNum = IOData.bytesToData(IO_HEADER.chunking_number.type, chunkingNumBytes);
    offset += IO_HEADER.chunking_number.size;

    var chunkingSizeBytes = new Uint8Array(IO_HEADER.chunking_size.size);
    IOData.ArrayCopy(chunkingSizeBytes, 0, headerBytes, offset, IO_HEADER.chunking_size.size);
    var chunkingSize = IOData.bytesToData(IO_HEADER.chunking_size.type, chunkingSizeBytes);
    offset += IO_HEADER.chunking_size.size;

    var crcCodeBytes = new Uint8Array(IO_HEADER.crc_code.size);
    IOData.ArrayCopy(crcCodeBytes, 0, headerBytes, offset, IO_HEADER.crc_code.size);
    var crcCode = IOData.bytesToData(IO_HEADER.crc_code.type, crcCodeBytes);
    offset += IO_HEADER.crc_code.size;

    this.checkMark = checkMark;
    this.messageId = messageId;
    this.dataType = dataType;
    this.sendType = sendType;
    this.nameSize = nameSize;
    this.dataSize = dataSize;
    this.chunkingTotalNum = chunkingTotalNum;
    this.chunkingNum = chunkingNum;
    this.chunkingSize = chunkingSize;
    this.crcCode = crcCode;
  }
}

class IOData {
  constructor()
  {
    this.header = null;
    this.body = null;
  }

  setHeader(header)
  {
    this.header = header;
  }
  getHeader()
  {
    return this.header;
  }

  setBody(data)
  {
    this.body = data;
  }
  getBody()
  {
    return this.body;
  }

  setIoData(header, data)
  {
    this.header = header;
    this.data = data;
  }

  setSendType(sendType = SEND_TYPE.ROOM)
  {
    this.header.setType(sendType);
    this.sendType = sendType;
  }
  
  static getEncodeData(data)
  {
    //Get Compression data
    var data = JsonToBytes(data);
  
    //Get Encryption data
  
    return data;
  }
  
  static getDecodeData(data)
  {
    //Get Decrypition data
  
    //Get Decompression data
    var data = BytesToJson(data);  
    return data;
  }

  static toBytes()
  {
    return this.dataToBytes(this.dataType, this.data);
  }

  static toData() {
    return this.bytesToData(this.dataType, this.data);
  }

  static ArrayCopy(targetArr, targetPos, srcArr, srcPos, size)
  {
    if (typeof srcArr === 'object') {
      srcArr = Object.values(srcArr);
    }
    var tmpArr = srcArr.slice(srcPos, srcPos + size);
    targetArr.set(tmpArr, targetPos);
    // Array.prototype.splice.apply(targetArr, [targetPos, size].concat(tmpArr));
    return targetArr;
  }

  static getCRCCode(chunkingBytes)
  {
    var chunkingSize = IOData.getLength(chunkingBytes);
    var crcBytes = new Uint8Array(IO_HEADER.crc_code.size);

    if (chunkingSize > 3)
    {
      var middlePos = Math.floor(chunkingSize / 2);
      crcBytes[0] = chunkingBytes[0] ^ 7;
      crcBytes[1] = chunkingBytes[middlePos] ^ 8;
      crcBytes[2] = chunkingBytes[chunkingSize - 1] ^ 9;
    } else {
      crcBytes[0] = chunkingBytes[0] ^ 7;
      crcBytes[1] = 5 ^ 8;
      crcBytes[2] = chunkingBytes[chunkingSize - 1] ^ 9;
    }
    
    var crc = IOData.bytesToData(IO_HEADER.crc_code.type, crcBytes);
    return crc;
  }

  static dataToBytes(type, data) {
    var bytes = [];

    switch(type) {
      case DATA_TYPE.JSON:
        var strData = JSON.stringify(data);
        for (var i = 0; i < IOData.getLength(strData); i++){  
          bytes.push(strData.charCodeAt(i));
        }
        break;
      case DATA_TYPE.STRING:
        var strData = data;
        for (var i = 0; i < IOData.getLength(strData); i++){  
          bytes.push(strData.charCodeAt(i));
        }
        break;
      case DATA_TYPE.BYTES:
        bytes = data;
        break;
      case DATA_TYPE.UINT32:
        bytes = [
          (data & 0x000000ff),
          (data & 0x0000ff00) >> 8,
          (data & 0x00ff0000) >> 16,
          (data & 0xff000000) >> 24
        ];
        break;
      case DATA_TYPE.UINT64:
        bytes = new Uint8Array([
          (data & 0x00000000000000ff),
          (data & 0x000000000000ff00) >> 8,
          (data & 0x0000000000ff0000) >> 16,
          (data & 0x00000000ff000000) >> 24,
          (data & 0x000000ff00000000) >> 32,      
          (data & 0xff00000000000000) >> 56,
          (data & 0x0000ff0000000000) >> 40,
          (data & 0x00ff000000000000) >> 48
        ]);
        break;
      case DATA_TYPE.BYTE:
        bytes = new Uint8Array([ (data & 0xff) ]);
        break;
    }
    return bytes;
  }

  static getLength(dataBytes)
  {
    if (dataBytes.length === undefined) {
      return Object.keys(dataBytes).length;
    } else {
      return dataBytes.length;
    }
  }

  static bytesToData(type, bytes) {
    var data = null;

    switch(type) {
      case DATA_TYPE.JSON:
        data = "";
        for(var i = 0; i < IOData.getLength(bytes); ++i){
          data += (String.fromCharCode(bytes[i]));
        }
        try {
          data = JSON.parse(data);
        } catch (e) {
        }
        break;
      case DATA_TYPE.STRING:
        data = "";
        for(var i = 0; i < IOData.getLength(bytes); ++i){
          data += (String.fromCharCode(bytes[i]));
        }
        break;
      case DATA_TYPE.BYTES:
        data = bytes;
        break;
      case DATA_TYPE.UINT32:
        var data1 = bytes[0] ? bytes[0] : 0;
        var data2 = bytes[1] ? bytes[1] : 0;
        var data3 = bytes[2] ? bytes[2] : 0;
        var data4 = bytes[3] ? bytes[3] : 0;
        data = (data4 << 24) + (data3 << 16) + (data2 << 8) + data1;
        break;
      case DATA_TYPE.UINT64:
        var data1 = bytes[0] ? bytes[0] : 0;
        var data2 = bytes[1] ? bytes[1] : 0;
        var data3 = bytes[2] ? bytes[2] : 0;
        var data4 = bytes[3] ? bytes[3] : 0;
        var data5 = bytes[4] ? bytes[4] : 0;
        var data6 = bytes[5] ? bytes[5] : 0;
        var data7 = bytes[6] ? bytes[6] : 0;
        var data8 = bytes[7] ? bytes[7] : 0;
        data = (data8 << 56) + (data7 << 48) + (data6 << 40) + (data5 << 32)
          + (data4 << 24) + (data3 << 16) + (data2 << 8) + data1;
        break;
      case DATA_TYPE.BYTE:
        data = bytes[0];
        break;
    }
    return data;
  }

  static getBytesWithCompression(data) {
    var data = pako.deflate(data);
    return data;
  }
  
  static getBytesWithDecompression(data) {
    var data = pako.inflate(data);
    // var inflator = new pako.Inflate();
  
    // inflator.push(data, true);
  
    // if (inflator.err) {
    //   return {};
    // }
    // data = inflator.result;
    return data;
  }
  
  static getBytesWithEncryption(key, data) {
    try {
      const encBytes = AesCtr.encrypt(data, key, 256);
      return encBytes;
    } catch {
      return null;
    }
  }

  static getBytesWithDecryption(key, data) {
    try {
      const decBytes = AesCtr.decrypt(data, key, 256);
      return decBytes;
    } catch {
      return null;
    }
  }

  static isCheckMarkStatus(dataBytes) {
    var checkMark = IOData.bytesToData(IO_HEADER.check_mark.type, dataBytes);
    return checkMark;
  }

  static checkBytesStatus(dataBytes) {
    var checkMarkBytes = new Uint8Array(IO_HEADER.check_mark.size);
    IOData.ArrayCopy(checkMarkBytes, 0, dataBytes, 0, IO_HEADER.check_mark.size);
    var checkMark = IOData.bytesToData(IO_HEADER.check_mark.type, checkMarkBytes);
    if (checkMark !== CHECK_MARK) {
      return false;
    }
    var dataSize = IOData.getLength(dataBytes);
    if (dataSize < HEADER_SIZE)
    {
      return false;
    }
    return true;
  }
}

class Channel {
  constructor(socket) 
  {
    this.connected = false;
    this.channelName = '';
    this.socket = socket;
    
    this.secretKey = '';
    this.clientKey = '';
    this.serverKey = '';
    this.userPubId = '';
    this.binds = {};
    this.arrPendingIoData = {};
  }
  setChannelValues(channelName, userPubId, secretKey, clientKey, serverKey='')
  {
    this.channelName = channelName;
    this.secretKey = secretKey;
    this.clientKey = clientKey;
    this.serverKey = serverKey;
    this.userPubId = userPubId;
  }
  connect()
  {
    this.sendData('ss_newconnection789321', {
      'channel_name': this.channelName,
      'user_pub_id': this.userPubId,
      'client_key': this.clientKey,
      'server_key': this.serverKey
    });
  }
  init()
  {
    this.bind('ss_newconnection789321', (data) => {
      this.connected = true;
    });
    this.socket.on('disconnect', () => {
      this.connected = false;
      if (typeof this.binds['ss_disconnect_me'] === "function")
      {
        this.binds['ss_disconnect_me']();
      }
    });
    this.socket.on('reconnect', () => {
      if (typeof this.binds['reconnect'] === "function")
      {
        this.binds['reconnect']();
      }
    });
    this.socket.on('reconnect_error', () => {
      if (typeof this.binds['reconnect_error'] === "function")
      {
        this.binds['reconnect_error']();
      }
    });
  }
  bind(type, func) {
    this.socket.on(type, (data) => {
      if (!this.connect) {
        return false;
      }
      if (type === undefined) {
        return false;
      }

      data = IOData.getBytesWithDecryption(this.secretKey, data);
      // data = IOData.getBytesWithDecompression(data);
      if (!data) { 
        return false;
      }
      if (!IOData.checkBytesStatus(data)) {
        return false;
      }
      var headerBytes = new Uint8Array(HEADER_SIZE);
      IOData.ArrayCopy(headerBytes, 0, data, 0, HEADER_SIZE);
      var ioHeader = new IODataHeader();
      ioHeader.updateFromBytes(data);
      var dataType = ioHeader.dataType;
      var nameSize = ioHeader.nameSize;
      var dataSize = ioHeader.dataSize;
      var crcCode1 = ioHeader.crcCode;

      var bodyBytesSize = ioHeader.chunkingSize - HEADER_SIZE;
      var bodyBytes = new Uint8Array(bodyBytesSize);
      IOData.ArrayCopy(bodyBytes, 0, data, HEADER_SIZE, bodyBytesSize);

      var crcCode2 = IOData.getCRCCode(bodyBytes);
      if (crcCode1 !== crcCode2) {
        return false;
      }

      var ioData = new IOData();
      var ioBody = new IODataBody(dataType);
      ioBody.setInitBytes(nameSize, dataSize);

      if (ioHeader.getChunkingStartStatus()) {
        this.arrPendingIoData = ioData;
      } else {
        if (this.arrPendingIoData !== undefined) {
          ioData = this.arrPendingIoData;
          ioBody = ioData.getBody();
        }
      }
      if (ioHeader.getChunkingEndStatus()) {
        ioBody.addDataFromBytes(bodyBytes);
        ioBody.updateDataFromBytes();
        ioData.setHeader(ioHeader);
        this.arrPendingIoData = undefined;
      } else {
        ioBody.addDataFromBytes(bodyBytes);
        ioData.setHeader(ioHeader);
        ioData.setBody(ioBody);
        this.arrPendingIoData = ioData;
        return true;
      }

      var dataType = ioHeader.dataType;
      var bodyData = ioBody.data;
      ioData.setHeader(ioHeader);
      ioData.setBody(ioBody);
      var msgName = ioBody.msgName;

      var bindFunc = this.binds[msgName];
      if (typeof bindFunc === 'function') {
        bindFunc(bodyData);
      }

    });
    this.binds[type] = func;
  }
  sendData(msgName, data = {}, dataType = DATA_TYPE.JSON) {
    if (!this.connect) {
      return false;
    }
    var sendType = SEND_TYPE.ROOM;
    SocketExt.sendData(this.socket, this.secretKey, msgName, sendType, dataType, data);
  }
  sendDataExcludeSender(msgName, data={}, dataType = DATA_TYPE.JSON) {
    if (!this.connect) {
      return false;
    }
    var sendType = SEND_TYPE.EXCLUDE_SENDER;
    SocketExt.sendData(this.socket, this.secretKey, msgName, sendType, dataType, data);
  }
}

class SocketExt {
  constructor(io, url = null, isSecure = true) {
    this.io = io;
    this.url = url;
    this.isSecure = isSecure;

    this.channels = {};
    this.secretKey = '';
    this.channelName = '';
    this.user = '';
    this.clientKey = '';
    this.serverKey = '';
    this.userPubId = '';
  }
  setKeys(userPubId, secretKey, clientKey, serverKey='')
  {
    this.userPubId = userPubId;
    this.secretKey = secretKey;
    this.clientKey = clientKey;
    this.serverKey = serverKey;
  }
  subscribe(channelName) {
    var secretKey = this.secretKey;
    var clientKey = this.clientKey;
    var serverKey = this.serverKey;
    var userPubId = this.userPubId;

    var channel = null;
    if (this.channels[channelName]) {
      channel = this.channels[channelName];
    } else {
      var socket = null;
      if (this.url) {
        if (this.isSecure) {
          socket = this.io(this.url, {
            'path': '/socket_server',
            // forceNew: true,
            secure: true,
            rejectUnauthorized: false
          });  
        } else {
          socket = this.io(this.url); 
        }
      } else {
        return false;
      }
      channel = new Channel(socket)
      channel.setChannelValues(channelName, userPubId, secretKey, clientKey, serverKey);
      this.channels[channelName] = channel;
      channel.init();
      channel.connect();
    }
    return channel;
  }
  static sendData(socket, secretKey, bindName, sendType, dataType, data) {
    var bodyData = new IODataBody(dataType);
    bodyData.setData(bindName, data);
    var ioBodyDataBytes = bodyData.generateBytes();
    var ioBodyDataBytesSize = IOData.getLength(ioBodyDataBytes);
    var nameSize = bodyData.msgNameSize;
    
    var chunkingNum = 0;
    var chunkingBytesSize = ioBodyDataBytesSize + HEADER_SIZE;
    
    if (chunkingBytesSize > MAX_CHUNKING_SIZE) {
      var chunkingTotalNum = Math.ceil(ioBodyDataBytesSize / MAX_CHUNKING_DATA_SIZE); 
      var messageId = 123456789;
      for (var num = 0; num < chunkingTotalNum; num ++) {
        chunkingNum = num + 1;
        var chunkingBodyBytes = bodyData.getChunkingBytes(chunkingNum);
        var chunkingBodySize = IOData.getLength(chunkingBodyBytes);
        var crcCode = IOData.getCRCCode(chunkingBodyBytes);
        var tmpChunkingBytesSize = chunkingBodySize + HEADER_SIZE;

        var ioHeader = new IODataHeader();
        ioHeader.setHeader(
          CHECK_MARK,
          messageId,
          sendType,
          dataType,
          nameSize,
          ioBodyDataBytesSize,
          chunkingTotalNum,
          chunkingNum,
          tmpChunkingBytesSize,
          crcCode
        );
        var headerBytes = ioHeader.generateBytes();
        
        var chunkingBytes = new Uint8Array(tmpChunkingBytesSize);
        IOData.ArrayCopy(chunkingBytes, 0, headerBytes, 0, HEADER_SIZE);
        IOData.ArrayCopy(chunkingBytes, HEADER_SIZE, chunkingBodyBytes, 0, chunkingBodySize);
        // chunkingBytes = IOData.getBytesWithCompression(chunkingBytes);
        chunkingBytes = IOData.getBytesWithEncryption(secretKey, chunkingBytes);
        socket.emit('message', chunkingBytes);
      }
    } else {
      var chunkingTotalNum = 1;
      var chunkingNum = 1;

      var chunkingBytes = new Uint8Array(chunkingBytesSize);
      
      var chunkingBodyBytes = ioBodyDataBytes;
      var chunkingBodySize = ioBodyDataBytesSize;
      var crc = IOData.getCRCCode(chunkingBodyBytes);
      
      var ioHeader = new IODataHeader();
      ioHeader.setHeader(
        CHECK_MARK,
        "message_id",
        sendType,
        dataType,
        nameSize,
        ioBodyDataBytesSize,
        chunkingTotalNum,
        chunkingNum,
        chunkingBytesSize,
        crc
      );

      var headerBytes = ioHeader.generateBytes();
      IOData.ArrayCopy(chunkingBytes, 0, headerBytes, 0, HEADER_SIZE);
      IOData.ArrayCopy(chunkingBytes, HEADER_SIZE, chunkingBodyBytes, 0, chunkingBodySize);
      // chunkingBytes = IOData.getBytesWithCompression(chunkingBytes);
      chunkingBytes = IOData.getBytesWithEncryption(secretKey, chunkingBytes);
      socket.emit('message', chunkingBytes);
    }
  }
}


/*
************************************************************
********************* SocketIO Server Code *****************
************************************************************
*/
class ChannelInfo {
  constructor(io) 
  {
    this.channelName = '';
    this.numConnects = 0;

    this.secretKey = '';
    this.clientKey = '';
    this.serverKey = '';
    this.io = io;
    this.isOn = false;
  }
  
  setChannelValues(channelName, secretKey, clientKey, serverKey='')
  {
    this.channelName = channelName;
    this.secretKey = secretKey;
    this.clientKey = clientKey;
    this.serverKey = serverKey;
  }
}

class SocketLib {
  constructor(io, secretKey) {
    if (!this.io) {
      this.io = io;
    }
    this.channels = {};
    this.binds = {};
    this.arrPendingIoData = {};

    this.funcForConnect = null;
    this.funcForDisconnect = null;
    this.funcForMessage = null;
    this.secretKey = secretKey;
  }

  setChannelInfo(channelName, channel) {
    this.channels[channelName] = channel;
  }
  getChannelInfo(channelName)
  {
    return this.channels[channelName];
  }
  
  bind(type, func) {
    this.binds[type] = func;
  }
  
  listen() {
    this.isOn = true;
    this.bind('ss_newconnection789321', (socket, channelName, data) => {
      if (socket.isConnected) {
        return false;
      }

      if (typeof this.binds['ss_newconnection'] === "function")
      {
        var retFlag = this.binds['ss_newconnection'](socket, channelName, data);
        if (!retFlag) {
          return false;
        }
      }
      var channelName = data.channel_name;
      var clientKey = data.client_key;
      var serverKey = data.server_key;
      var userPubId = data.user_pub_id;
      var channel = null;
      if (this.channels[channelName] !== undefined) {
        channel = this.getChannelInfo(channelName);
      } else {
        channel = new ChannelInfo(this.io);
        channel.setChannelValues(channelName, this.secretKey, clientKey, serverKey);
        this.setChannelInfo(channelName, channel);
      }
      socket.join(channelName);
      socket.channelName = channelName;
      socket.isConnected = true;
      socket.serverKey = serverKey;
      socket.userPubId = userPubId;

      ++channel.numConnects;
      ++this.numConnects;

      var sendData = { 'connection': 'ok' };
      this.sendDataToSender(socket, channelName, 'ss_newconnection789321', sendData, DATA_TYPE.JSON);
      if (serverKey != '') {
        return false;
      }
      sendData = { 'user_pub_id': userPubId};
      this.sendData(socket, channelName, 'ss_newconnection', sendData, DATA_TYPE.JSON);
      return false;
    });

    this.io.on('connection', (socket) => {
      socket.on('disconnect', () => {
        var channelName = socket.channelName;
        if (typeof this.binds['ss_disconnect'] === "function") {
          if (!this.binds['ss_disconnect'](socket, channelName)) {
            return;
          }
        }
        var sendData = { 'user_pub_id': socket.userPubId };
        this.sendData(socket, channelName, 'ss_disconnect', sendData, DATA_TYPE.JSON);
        --this.numConnects;
      });
      // for (const keyName in this.binds) {
        socket.on('message', (data) => {
          // if (keyName === undefined) {
          //   return null;
          // }
          data = IOData.getBytesWithDecryption(this.secretKey, data);
          // data = IOData.getBytesWithDecompression(data);
          if (!IOData.checkBytesStatus(data)) {
            return false;
          }
    
          var headerBytes = new Uint8Array(HEADER_SIZE);
          IOData.ArrayCopy(headerBytes, 0, data, 0, HEADER_SIZE);
          var ioHeader = new IODataHeader();
          ioHeader.updateFromBytes(data);
          var dataType = ioHeader.dataType;
          var nameSize = ioHeader.nameSize;
          var dataSize = ioHeader.dataSize;
          var crcCode1 = ioHeader.crcCode;
      
          var bodyBytesSize = ioHeader.chunkingSize - HEADER_SIZE;
          var bodyBytes = new Uint8Array(bodyBytesSize);
          IOData.ArrayCopy(bodyBytes, 0, data, HEADER_SIZE, bodyBytesSize);
      
          var crcCode2 = IOData.getCRCCode(bodyBytes);
          if (crcCode1 !== crcCode2) {
            return false;
          }
      
          var sockId = socket.id;
          var ioData = new IOData(this.secretKey);
          var ioBody = new IODataBody(dataType);
          ioBody.setInitBytes(nameSize, dataSize);
      
          if (ioHeader.getChunkingStartStatus()) {
            this.arrPendingIoData[sockId] = ioData;
          } else {
            if (this.arrPendingIoData[sockId] !== undefined) {
              ioData = this.arrPendingIoData[sockId];
              ioBody = ioData.getBody();
            }
          }
          if (ioHeader.getChunkingEndStatus()) {
            ioBody.addDataFromBytes(bodyBytes);
            ioBody.updateDataFromBytes();
            ioData.setHeader(ioHeader);
            this.arrPendingIoData[sockId] = undefined;
          } else {
            ioBody.addDataFromBytes(bodyBytes);
            ioData.setHeader(ioHeader);
            ioData.setBody(ioBody);
            this.arrPendingIoData[sockId] = ioData;
            return true;
          }
          var msgName = ioBody.msgName;
          
          ioData.setHeader(ioHeader);
          ioData.setBody(ioBody);

          var dataType = ioHeader.dataType;
          var sendType = ioHeader.sendType;
          var bodyData = ioBody.data;
          var msgName = ioBody.msgName;
          var secretKey = this.secretKey;
              
          var bindFunc = this.binds[msgName];
          var channelName = socket.channelName;
          if (typeof bindFunc === 'function') {
            var sendFlag = bindFunc(socket, channelName, bodyData);
            if (sendFlag) {
              SocketLib.sendData(this.io, socket, secretKey, channelName, msgName, bodyData, dataType, sendType)
            }
          } else {
            SocketLib.sendData(this.io, socket, secretKey, channelName, msgName, bodyData, dataType, sendType)
          }
        });
      // }
    });
  }
  sendData(socket, channelName, msgName, data, dataType = DATA_TYPE.JSON)
  {
    var sendType = SEND_TYPE.ROOM;
    var secretKey = this.secretKey;
    SocketLib.sendData(this.io, socket, secretKey, channelName, msgName, data, dataType, sendType);
  }
  sendDataToSender(socket, channelName, msgName, data, dataType = DATA_TYPE.JSON)
  {
    var sendType = SEND_TYPE.ONLY_SENDER;
    var secretKey = this.secretKey;
    SocketLib.sendData(this.io, socket, secretKey, channelName, msgName, data, dataType, sendType);
  }
  sendDataExcludSender(socket, channelName, msgName, data, dataType = DATA_TYPE.JSON)
  {
    var sendType = SEND_TYPE.EXCLUDE_SENDER;
    var secretKey = this.secretKey;
    SocketLib.sendData(this.io, socket, secretKey, channelName, msgName, data, dataType, sendType);
  }
  sendDataAll(socket, channelName, msgName, data, dataType = DATA_TYPE.JSON)
  {
    var sendType = SEND_TYPE.ALL;
    var secretKey = this.secretKey;
    SocketLib.sendData(this.io, socket, secretKey, channelName, msgName, data, dataType, sendType);
  }
  static sendData(io, socket, secretKey, channelName, bindName, data, dataType, sendType) {
    var bodyData = new IODataBody(dataType);
    bodyData.setData(bindName, data);
    var ioBodyDataBytes = bodyData.generateBytes();
    var ioBodyDataBytesSize = IOData.getLength(ioBodyDataBytes);
    var nameSize = bodyData.msgNameSize;
    
    var chunkingNum = 0;
    var chunkingBytesSize = ioBodyDataBytesSize + HEADER_SIZE;
    
    if (chunkingBytesSize > MAX_CHUNKING_SIZE) {
      var chunkingTotalNum = Math.ceil(ioBodyDataBytesSize / MAX_CHUNKING_DATA_SIZE ); 
      var messageId = generateMessageId();
      for (var num = 0; num < chunkingTotalNum; num ++) {
        chunkingNum = num + 1;
        var chunkingBodyBytes = bodyData.getChunkingBytes(chunkingNum);
        var chunkingBodySize = IOData.getLength(chunkingBodyBytes);
        var crcCode = IOData.getCRCCode(chunkingBodyBytes);
        var tmpChunkingBytesSize = chunkingBodySize + HEADER_SIZE;

        var ioHeader = new IODataHeader();
        ioHeader.setHeader(
          CHECK_MARK,
          messageId,
          sendType,
          dataType,
          nameSize,
          ioBodyDataBytesSize,
          chunkingTotalNum,
          chunkingNum,
          tmpChunkingBytesSize,
          crcCode
        );
        var headerBytes = ioHeader.generateBytes();
        
        var chunkingBytes = new Uint8Array(tmpChunkingBytesSize);
        IOData.ArrayCopy(chunkingBytes, 0, headerBytes, 0, HEADER_SIZE);
        IOData.ArrayCopy(chunkingBytes, HEADER_SIZE, chunkingBodyBytes, 0, chunkingBodySize);
        // chunkingBytes = IOData.getBytesWithCompression(chunkingBytes);
        chunkingBytes = IOData.getBytesWithEncryption(secretKey, chunkingBytes);
        SocketLib.sendDataWithType(io, socket, channelName, bindName, sendType, chunkingBytes);
      }
    } else {
      var chunkingTotalNum = 1;
      var chunkingNum = 1;

      var chunkingBytes = new Uint8Array(chunkingBytesSize);
      
      var chunkingBodyBytes = ioBodyDataBytes;
      var chunkingBodySize = ioBodyDataBytesSize;
      var crc = IOData.getCRCCode(chunkingBodyBytes);
      
      var ioHeader = new IODataHeader();
      ioHeader.setHeader(
        CHECK_MARK,
        generateMessageId(),
        sendType,
        dataType,
        nameSize,
        ioBodyDataBytesSize,
        chunkingTotalNum,
        chunkingNum,
        chunkingBytesSize,
        crc
      );

      var headerBytes = ioHeader.generateBytes();
      IOData.ArrayCopy(chunkingBytes, 0, headerBytes, 0, HEADER_SIZE);
      IOData.ArrayCopy(chunkingBytes, HEADER_SIZE, chunkingBodyBytes, 0, chunkingBodySize);
      // chunkingBytes = IOData.getBytesWithCompression(chunkingBytes);
      chunkingBytes = IOData.getBytesWithEncryption(secretKey, chunkingBytes);
      SocketLib.sendDataWithType(io, socket, channelName, bindName, sendType, chunkingBytes);
    }
  }

  static sendDataWithType(io, socket, channelName, bindName, sendType, chunkingBytes)
  {
    switch (sendType) {
      case SEND_TYPE.ROOM:
        io.to(channelName).emit(bindName, chunkingBytes);
        break;
      case SEND_TYPE.EXCLUDE_SENDER:
        socket.broadcast.to(channelName).emit(bindName, chunkingBytes);
        break;
      case SEND_TYPE.ONLY_SERVER:
        break; 
      case SEND_TYPE.ONLY_SENDER:
        socket.emit(bindName, chunkingBytes);
        break;
      case SEND_TYPE.ALL:
        io.emit(bindName, chunkingBytes);
        break;
    }
  }
}

function generateMessageId()
{
  var msgId = Math.random() * 987654321012;
  var msgIdBytes = IOData.dataToBytes(DATA_TYPE.UINT64, msgId);
  return msgIdBytes;
}

module.exports = {
  SocketExt : SocketExt,
  SocketLib: SocketLib
}
