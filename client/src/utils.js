export function decToHexString(number, size){

    // Redundant
    if (number < 0)
    {
      number = 0xFFFFFFFF + number + 1;
    }
    
    let hex = Number(number).toString(16).toUpperCase();
    return "0x" + hex.padStart(size, "0");    
}

export function decToBinaryString(number){
  return Number(number).toString(2).padStart(22, "0");  
}
