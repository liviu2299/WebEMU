export const handleRun = (setEmulator,input,emulator) => {
  (async () => {
      const rawResponse = await fetch("/compute", {
          method: "POST",
          headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
          },
          body: JSON.stringify({ data: input }),
      });

      const content = await rawResponse.json();

      if(content.error === "None")    
          setEmulator({...emulator, MEMORY: {...emulator.MEMORY, data:content.memory}, REGISTERS: content.registers, ERROR: content.error, LOG: content.log, STATE: content.state})
      else
          setEmulator({...emulator, ERROR: content.error, LOG: content.log, STATE: content.state})

  })();
}

export const handleStep = (setEmulator,input,emulator) => {
(async () => {
    const rawResponse = await fetch("/step", {
        method: "POST",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ data: input }),
    });

    const content = await rawResponse.json();

    if(content.error === "None")    
        setEmulator({...emulator, MEMORY: {...emulator.MEMORY, data:content.memory}, REGISTERS: content.registers, ERROR: content.error, LOG: content.log, STATE: content.state})
    else
        setEmulator({...emulator, ERROR: content.error, LOG: content.log, STATE: content.state})

})();
}

export const handleAssemble = (setEmulator,input,emulator) => {
  (async () => {
      const rawResponse = await fetch("/compile", {
          method: "POST",
          headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
          },
          body: JSON.stringify({ data: input }),
      });

      const content = await rawResponse.json();

      if(content.error === "None")   
          setEmulator({...emulator, MEMORY: {...emulator.MEMORY, data:content.memory}, ERROR: content.error, LOG: content.log, STATE: content.state})
      else
          setEmulator({...emulator, ERROR: content.error, LOG: content.log, STATE: content.state})

  })();
} 