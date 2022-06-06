let index = 0x10000A - 0x100000
let size = 0x8

let start = index
let end = index+size

for(let i=0; i<end-start; i++){
  let pos = start+i
  console.log('Row' + Math.trunc(pos/16))
  console.log('Column:' + pos%16)
}


//console.log(start)
//console.log(end)