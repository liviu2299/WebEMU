function decToBinaryString(number){
    return Number(number).toString(2).padStart(22, "0");  
}

let temp = decToBinaryString(582)



console.log(decToBinaryString(531).split("").reverse()[1])