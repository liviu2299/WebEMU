export function decToHexString(number, size){    
    let hex = Number(number).toString(16).toUpperCase();
    return "0x" + hex.padStart(size, "0");    
}

export function decToHex(number){
  return Number(number).toString(16).toUpperCase();
}

export function decToBinaryString(number){
  return Number(number).toString(2).padStart(22, "0");  
}

export function decToASCII(number){ 
  if(number <= 126 && number >= 32) return String.fromCharCode(number);
  return '.';
}