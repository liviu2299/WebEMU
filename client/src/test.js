function decToASCII(number){
    let no = String.fromCharCode(0);
    let temp = String.fromCharCode(number);

    if(temp === no) return '.'

    return temp;
}

for(let i=0; i<255; i++){
    console.log(i + ' ' + decToASCII(i))
}
