use std::collections::HashMap;
use std::env;
use std::process;

use wash::spawn;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let command = match args.next() {
        Some(cmd) => cmd,
        None => {
            println!("nohup: missing operand");
            process::exit(1);
        }
    };

    /*process::exit(
        spawn(&command, &args.map().collect(), &HashMap::new(), true, &[]).output.parse()?
    );*/
    Ok(())
}
