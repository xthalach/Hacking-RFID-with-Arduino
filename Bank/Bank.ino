// Librerías
#include <SPI.h>
#include <MFRC522.h>
 
// Pines SPI
#define RST_PIN 9
#define SS_PIN 10
 
// Instancia a la clase MFRC522
MFRC522 mfrc522(SS_PIN, RST_PIN);
 
// Clave de cifrado actuales
MFRC522::MIFARE_Key keyA = {keyByte: {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
MFRC522::MIFARE_Key keyB = {keyByte: {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
 
// Número de viajes array 16 bytes
byte datosBloque[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
 
// Datos del sector
byte sector = 15;
byte numBlque = 60;
byte bloqueTrailer = 63;
byte numViajes = 10;


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
  Serial.println(F("Acerca la tarjeta al lector para escanear...."));
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
 
  
  // Obtener viajes acutales
  byte viajesActuales = leerViajes();
  Serial.println("");
  Serial.print(F("Viajes actuales: "));
  Serial.println(viajesActuales, DEC);

  Serial.print(F("Se van a cargar "));
  Serial.print(numViajes);
  Serial.println(F(" viajes"));  

  // Añadir viajes a los actuales
  viajesActuales = viajesActuales + numViajes;
  datosBloque[0] = viajesActuales;
 
  // Escribir la información en el bloque
  int resultadoEb = escribirBloque();
 
  // Dependiendo del resultado
  if (resultadoEb == 1) {
    Serial.println(F("No se puede escribir en un bloque Trailer"));
  } else if (resultadoEb == 2) {
    Serial.println(F("No se puede escribir en un bloque del fabricante"));
  } else if (resultadoEb == 3) {
    Serial.println(F("Problemas al comunicar con la clave proporcionada"));
  } else if (resultadoEb == 4) {
    Serial.println(F("Problemas al escribir en el bloque"));
  } else {
    Serial.println(F("Se han guardado los datos correctamente"));
    byte totalViajes = leerViajes();
    Serial.println("");
    Serial.print(F("Viajes actualizados: "));
    // Leer los datos del bloque
    Serial.println(totalViajes, DEC);
  }
 
  // Detener el lector
  mfrc522.PICC_HaltA();
  // Detener la encriptación Crypto1
  mfrc522.PCD_StopCrypto1();
 
  Serial.println();
  Serial.println(F("Proceso finalizado. Ya puedes retirar la tarjeta del lector RFID"));
 
  while (true);
 
}
 
byte escribirBloque() {
  MFRC522::StatusCode estado;
 
  // Comenzar comunicación cifrada con Key-A
  estado = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, bloqueTrailer, &keyA, &(mfrc522.uid));
  if (estado != MFRC522::STATUS_OK) {
    return 3;
  }
 
  // Escribir en el bloque
  Serial.print(F("Bloque numeroBloque: "));
  //Serial.println(numBlque);
  estado = mfrc522.MIFARE_Write(numBlque, datosBloque, 16);
  if (estado != MFRC522::STATUS_OK) {
    Serial.print("MIFARE_Write() fallo: ");
    Serial.println(mfrc522.GetStatusCodeName(estado));
    return 4;
  }
 
  return 0;
}
 
byte leerViajes()
{
  MFRC522::StatusCode estado;
  byte datosLectura[18];
  byte tamBuffer = 18;
 
  // Comenzar comunicación cifrada con Key-A
  estado = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, bloqueTrailer, &keyA, &(mfrc522.uid));
  if (estado != MFRC522::STATUS_OK) {
    return 1;
  }
 
  // Leer bloque
  estado = mfrc522.MIFARE_Read(numBlque, datosLectura, &tamBuffer);
  if (estado != MFRC522::STATUS_OK) {
    Serial.print("MIFARE_Read() fallo: ");
    Serial.println(mfrc522.GetStatusCodeName(estado));
    return 2;
  }
  //mostrarByteArray(datosLectura, tamBuffer);
  return datosLectura[0];
}