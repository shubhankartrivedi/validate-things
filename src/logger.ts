export function logWithPrefix({message, type}:{
    message: string,
    type: "success" | "error"
}): void {
    if (type === "success") {
        console.log("\x1b[32m", "[log] validate-things >" ,"\x1b[0m",message) ; 
    } else {
        console.log("\x1b[31m", "[log] validate-things >" ,"\x1b[0m",message) ; 
    }
}


