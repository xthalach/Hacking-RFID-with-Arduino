#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN 9
#define SS_PIN 10
MFRC522 mfrc522(SS_PIN,RST_PIN);
MFRC522::MIFARE_Key key;
MFRC522::StatusCode status;

// Variables
int choice;
int count;
byte validKey1[4] = { 0x20, 0xD9, 0x6D, 0x3F };  // Ejemplo de clave valida

byte buffer[18];
byte block = 1;
byte len = 18;
int num;

// Funciones

//Función para comparar dos vectores
bool isEqualArray(byte* arrayA, byte* arrayB)
{
  for (int index = 0; index < sizeof(arrayA); index++)
  {
    if (arrayA[index] != arrayB[index]) return false;
  }
  return true;
}


void setup() {
  Serial.begin(9600);
  while(!Serial);
  SPI.begin();
  // Key 
  mfrc522.PCD_Init();
  for (byte i =0; i < 6; i++){
    key.keyByte[i] = 0xFF;
  }
  Serial.println("Control Access");
  Serial.println("[1] Simple Control Access");
  Serial.println("[2] Hard Control Access");
}

void loop() {

  choice = Serial.read();

  if(choice == '1')
  {
    Serial.println("Inside Simple Control Access Function");
    Serial.println("Insert Card...");
    count=0;
    while(count < 50){
      if (mfrc522.PICC_IsNewCardPresent())
      {
        //Seleccionamos una tarjeta
        if (mfrc522.PICC_ReadCardSerial())
        {
          // Comparar ID con las claves válidas
          if (isEqualArray(mfrc522.uid.uidByte, validKey1))
            Serial.println("Tarjeta valida");
          else
            Serial.println("Tarjeta invalida");
    
          // Finalizar lectura actual
          count++;
        }
      }
  }
  }
  else if (choice == '2'){
    Serial.println("Insede Hard Control Access Function ");
    Serial.println("Insert Card...");
      num=0;  
    while(num < 10){
      if (mfrc522.PICC_IsNewCardPresent())
      {
        //Seleccionamos una tarjeta
        if (mfrc522.PICC_ReadCardSerial())
        {
            status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 1, &key, &(mfrc522.uid)); //line 834 of MFRC522.cpp file
          if (status != MFRC522::STATUS_OK) {
            Serial.print(F("Authentication failed: "));
            Serial.println(mfrc522.GetStatusCodeName(status));
            return;
          }  
          status = mfrc522.MIFARE_Read(block, buffer, &len);
          if (status != MFRC522::STATUS_OK) {
            Serial.print(F("Reading failed: "));
            Serial.println(mfrc522.GetStatusCodeName(status));
            return;
          }

          //PRINT FIRST NAME
          char Rol[16];
          for (uint8_t i = 5; i < 16; i++)
          {
            if (buffer[i] != 32)
            {
              Rol[i] =+ buffer[i];
            }
          }

          // Comparar ID con las claves válidas
          if (isEqualArray(mfrc522.uid.uidByte, validKey1)){
            if (strstr(Rol, "DomainAdmin")){
              Serial.println("Tarjeta valida");
            }else {
              Serial.println("Invalid Rol");
            }

          } else {
            Serial.println("Invalid UID ");
          }      
            num++;
            // Detener el lector
            mfrc522.PICC_HaltA();
            // Detener la encriptación Crypto1
            mfrc522.PCD_StopCrypto1();          
        }
      }
    }
  }
}
