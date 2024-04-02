export function logWithPrefix(message: string): void {
    console.log("\x1b[31m", "[log] validate-things >" ,"\x1b[0m",message) ; 
}


