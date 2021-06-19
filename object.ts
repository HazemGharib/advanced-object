import {Buffer} from 'buffer';
import {AES, enc} from 'crypto-js';

export class Object {
  private object: Object;
  private encrypted: boolean;
  constructor(object: any, private sealed: boolean = false) {
    this.object = object;
    this.sealed = sealed;
    this.encrypted = false;
  }

  // Private methods

  private purge(): void {
    this.object = new Object({}, this.sealed);    
  }

  // Static methods

  public static parse(object: string): Object {
    return new Object(JSON.parse(object));
  }

  public static base64Encode(object: Object): string {
    return Buffer.from(JSON.stringify(object), 'binary').toString('base64');
  }

  public static base64Decode(object: string): Object {
    return Object.parse(Buffer.from(object, 'base64').toString('binary'));
  }

  // Non static methods

  public toString(): string {
    if(this.isEncrypted()) return;
    return JSON.stringify(this.object);
  }

  public clone(): Object {
    if(this.isEncrypted()) return;
    return new Object(this.object, this.sealed);
  }

  public extend(object: any): Object {
    if(this.isEncrypted()) return;
    if(this.sealed) throw({error: 'Object is sealed'});
    return new Object({
      ...this.object,
      ...object
    });
  }

  public hasKey(key: string): boolean {
    if(this.isEncrypted()) return;
    return this.getKeys().some(objectKey => objectKey === key);
  }

  public getKeys(): Array<string> {
    if(this.isEncrypted()) return;
    return [...globalThis.Object.keys(this.object)];
  }

  public forEachKey(callBack: (key:string, value: any) => void): void {
    if(this.isEncrypted()) return;
    this.getKeys().forEach(key => callBack(key, this.object[key]));
  }

  public isSealed(): boolean {
    if(this.isEncrypted()) return;
    return this.sealed;
  }

  public seal(): Object {
    if(this.isEncrypted()) return;
    return new Object(this.object, true);
  }
  
  public isEncrypted(): boolean {
    return this.encrypted;
  }

  public aesEncrypt(key: string) {
    const cipher = AES.encrypt(this.toString(), key).toString();
    const encryptedObject = new Object(cipher);
    encryptedObject.encrypted = true;
    return encryptedObject;
  }

  public aesDecrypt(key: string) {  
    const decryptedObject = new Object (JSON.parse(AES.decrypt(this.object.toString(), key).toString(enc.Utf8)));
    decryptedObject.encrypted = false;
    return decryptedObject;
  }
}

console.log('----------------------------------------------------');
const x1 = new Object({name: 'Test'}, false);
console.log(x1.isSealed());
console.log('----------------------------------------------------');
const x2 = x1.extend({age: 18});
console.log(x2.toString());
console.log(x2.getKeys());
console.log(x2.isSealed());
console.log('----------------------------------------------------');
console.log(Object.parse('{"name": "Test"}'));
console.log('----------------------------------------------------');
x2.forEachKey((key, value) => {
  console.log(`The value of ${key} is ${value}`);
});
console.log('----------------------------------------------------');
const x2Encoded = Object.base64Encode(x2);
console.log(x2Encoded);

const x2Decoded = Object.base64Decode(x2Encoded);
console.log(x2Decoded.toString());
console.log('----------------------------------------------------');
console.log('encrypted:');
console.log(`Is sealed before encryption? ${x2.isSealed()}`);
const encryptedObject = x2.aesEncrypt('Hello World!!');
console.log(encryptedObject);
console.log(`Is encrypted? ${encryptedObject.isEncrypted()}`);
console.log(`To string after encryption? ${encryptedObject.toString()}`);
console.log(`Is sealed after encryption? ${encryptedObject.isSealed()}`);
const decryptedObject = encryptedObject.aesDecrypt('Hello World!!'); 
console.log(decryptedObject);
console.log(`Is encrypted? ${decryptedObject.isEncrypted()}`);
console.log(`To string after decryption? ${decryptedObject.toString()}`);
console.log(`Is sealed after decryption? ${decryptedObject.isSealed()}`);
console.log('----------------------------------------------------');
