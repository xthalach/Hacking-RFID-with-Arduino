// Librerías
#include <SPI.h>
#include <MFRC522.h>
 
// Pines SPI
#define RST_PIN 9
#define SS_PIN 10
 
// Instancia a la clase MFRC522
MFRC522 mfrc522(SS_PIN, RST_PIN);
 
// Claves de cifrado actuales
MFRC522::MIFARE_Key keyA = {keyByte: {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
MFRC522::MIFARE_Key keyB = {keyByte: {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
 
// Nuevas claves de cifrado
MFRC522::MIFARE_Key nuevaKeyA = {keyByte: {0xE6, 0x56, 0x1B, 0x95, 0x5A, 0x56}};

MFRC522::MIFARE_Key nuevaKeyB = {keyByte: {0xE6, 0x38, 0xC2, 0xA2, 0x74, 0xFF}};
 
// Datos del sector
byte sector = 15;
 
void mostrarByteArray(byte* buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}
 
void setup() {
  Serial.begin(9600);
  while (!Serial);      // Bucle que no permite continuar hasta que no se ha abierto el monitor serie
  SPI.begin();          // Iniciar bus SPI
  mfrc522.PCD_Init();   // Iniciar lector RFID RC522
 
  Serial.println(F("Acerca la tarjeta al lector para escanear."));
  Serial.println(F("Las claves de esta tarjeta deben ser:"));
  Serial.print("Key-A: ");
  mostrarByteArray(keyA.keyByte, MFRC522::MF_KEY_SIZE);
  Serial.println();
  Serial.print("Key-B: ");
  mostrarByteArray(keyB.keyByte, MFRC522::MF_KEY_SIZE);
  Serial.println();
  Serial.println(F("MUY IMPORTANTE: durante el proceso de actualización de las claves "));
  Serial.println(F("no separes la tarjeta del lector hasta que no termine."));
 
}
 
void loop() {
  // Si no hay una tarjeta cerca no sigue el programa
  if (!mfrc522.PICC_IsNewCardPresent()) {
    return;
  }
 
  // Si hay una tarjeta cerca, que la eleccione
  // En caso contrario que no continúe
  if (!mfrc522.PICC_ReadCardSerial()) {
    return;
  }
 
  // Mostrar información de la tarjeta por el monitor serie
  Serial.print(F("UID de la tarjeta:"));
  mostrarByteArray(mfrc522.uid.uidByte, mfrc522.uid.size);  // Motrar el UID
  Serial.println();
  Serial.print(F("Tipo de tarjeta: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);  //Motrar el tipo
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
 
  // Cambiar claves Key-A y Key-B en un sector concreto
  boolean resultado = cambiarKeys(&keyA, &keyB, &nuevaKeyA, &nuevaKeyB, sector);
 
  if (resultado) {
    Serial.print(F("Claves del sector "));
    Serial.println(sector);
    Serial.print(F("Key-A: "));
    mostrarByteArray(nuevaKeyA.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();
    Serial.print(F("Key-B: "));
    mostrarByteArray(nuevaKeyB.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();
  } else {
    Serial.print(F("Claves del sector "));
    Serial.println(sector);
    Serial.print(F("Key-A: "));
    mostrarByteArray(keyA.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();
    Serial.print(F("Key-B: "));
    mostrarByteArray(keyB.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();
  }
 
  // Detener el lector
  mfrc522.PICC_HaltA();
  // Detener la encriptación Crypto1
  mfrc522.PCD_StopCrypto1();
 
  Serial.println(F("Proceso finalizado. Ya puedes retirar la tarjeta del lector RFID"));
 
}
 
boolean cambiarKeys(MFRC522::MIFARE_Key* antiguaKeyA, MFRC522::MIFARE_Key* antiguaKeyB,
                    MFRC522::MIFARE_Key* nuevaKeyA, MFRC522::MIFARE_Key* nuevaKeyB,
                    int sector) {
 
  MFRC522::StatusCode estado;
  byte bloqueTrailer = sector * 4 + 3; // Cálculo del bloque Trailer
  byte buffer[18];
  byte size = sizeof(buffer);
 
  Serial.print(F("Modificando sector "));
  Serial.println(sector);
 
  // Autenticar utilizando la clave Key-A
  estado = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, bloqueTrailer, antiguaKeyA, &(mfrc522.uid));
 
  // Si no consigue autenticar que no continúe
  if (estado != MFRC522::STATUS_OK) {
    Serial.print(F("Fallo en la autenticación Key-A: "));
    Serial.println(mfrc522.GetStatusCodeName(estado));
    return false;
  }
 
  // Mostrar el sector completo
  Serial.println(F("Informción en el sector:"));
  mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), antiguaKeyA, sector);
  Serial.println();
 
  // Leyendo datos del bloque
  Serial.print(F("Leyendo datos del bloque ")); Serial.print(bloqueTrailer);
  Serial.println(F(" ..."));
  estado = (MFRC522::StatusCode) mfrc522.MIFARE_Read(bloqueTrailer, buffer, &size);
  if (estado != MFRC522::STATUS_OK) {
    Serial.print(F("Fallo al leer el bloque: "));
    Serial.println(mfrc522.GetStatusCodeName(estado));
    return false;
  }
  Serial.print(F("Información en el bloque ")); Serial.print(bloqueTrailer); Serial.println(F(":"));
  mostrarByteArray(buffer, 16); Serial.println();
  Serial.println();
 
  // Autenticar utilizando la clave Key-B
  estado = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, bloqueTrailer, antiguaKeyB, &(mfrc522.uid));
 
  // Si no consigue autenticar que no continúe
  if (estado != MFRC522::STATUS_OK) {
    Serial.print(F("Fallo en la uatenticación Key-B: "));
    Serial.println(mfrc522.GetStatusCodeName(estado));
    return false;
  }
 
  // Array con nuevas claves Key-A y Key-B
  if (nuevaKeyA != nullptr || nuevaKeyB != nullptr) {
    // Recorrer todos los bytes de la clave
    for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
      if (nuevaKeyA != nullptr) {
        buffer[i] = nuevaKeyA->keyByte[i];
      }
      if (nuevaKeyB != nullptr) {
        buffer[i + 10] = nuevaKeyB->keyByte[i];
      }
    }
  }
 
  // Escribir las nuevas claves al bloque Trailer
  estado = (MFRC522::StatusCode) mfrc522.MIFARE_Write(bloqueTrailer, buffer, 16);
  if (estado != MFRC522::STATUS_OK) {
    Serial.print(F("Fallo al escribir el bloque Trailer: "));
    Serial.println(mfrc522.GetStatusCodeName(estado));
    return false;
  }
 
  return true;
}