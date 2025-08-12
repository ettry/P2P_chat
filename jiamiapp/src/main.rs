use aes::Aes128;
use base64::{Engine as _, engine::general_purpose};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use chrono::{Local, TimeZone};
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use std::env;
use std::io;

fn main() {
    let args: Vec<String> = env::args().collect();
    // let local_time = Local::now().timestamp() as u64;
    let now = Local::now();
    let today = now.date_naive();
    let zero_clock = Local
        .from_local_datetime(&today.and_hms_opt(0, 0, 0).unwrap())
        .unwrap();
    let local_time = BigInt::from(zero_clock.timestamp()); // 0 点的时间戳，每天只变一次
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("读取失败");
    input = input.trim_end().to_string();
    let mut mima = String::new();
    if args.len() >= 2 {
        mima.push_str(&args[1]);
    }
    mima.push_str(local_time.to_string().as_str());
    let mut hasher = Sha256::new();
    hasher.update(mima.as_bytes());
    let result = hasher.finalize(); // 得到32字节的哈希值

    // 取前16字节做key，后16字节做iv
    let key: [u8; 16] = result[..16].try_into().unwrap();
    let iv: [u8; 16] = result[16..].try_into().unwrap();
    let vi = general_purpose::STANDARD.encode(iv);

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    if input.starts_with("he:") {
        let encrypted = aes_encrypt(&input, &key, &iv);
        let mut record = Vec::new();
        let encoded = general_purpose::STANDARD.encode(&encrypted);
        for c in encoded.chars() {
            record.push(c as u32);
        }
        let mut bytes: Vec<u8> = Vec::new();
        for code in record {
            bytes.extend(&code.to_be_bytes());
        }
        let base64 = general_purpose::STANDARD.encode(&bytes);
        if args.len() >= 2 {
            println!("{base64}:::::::::{vi}{}", args[1]);
        } else {
            println!("{base64}:::::::::{vi}");
        }
    } else {
        // let yyy: String = input
        //     .chars()
        //     .take(input.trim_end().chars().count() - 5)
        //     .collect();

        let bytes = general_purpose::STANDARD.decode(&input).unwrap();
        let mut record: Vec<u32> = Vec::new();
        for chunk in bytes.chunks(4) {
            let arr: [u8; 4] = chunk.try_into().unwrap();
            record.push(u32::from_be_bytes(arr));
        }
        let encoded: String = record.iter().map(|&c| char::from_u32(c).unwrap()).collect();
        let encrypted = general_purpose::STANDARD.decode(&encoded).unwrap();
        // let decrypted = aes_decrypt(
        //     &encrypted,
        //     mima.as_bytes().try_into().unwrap(),
        //     vi.as_bytes().try_into().unwrap(),
        // );
        match aes_decrypt(&encrypted, &key, &iv) {
            Ok(decrypted) => {
                if args.len() >= 2 {
                    println!(
                        "{}:::::::::{vi}{}",
                        String::from_utf8_lossy(&decrypted).trim_end(),
                        args[1]
                    );
                } else {
                    println!(
                        "{}:::::::::{vi}",
                        String::from_utf8_lossy(&decrypted).trim_end()
                    );
                }
            }
            Err(e) => println!("解密失败: {e:?}"),
        }

        // println!("原文：{}", String::from_utf8_lossy(&decrypted));
    }
}

fn aes_encrypt(plain_text: &str, key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(plain_text.as_bytes())
}

fn aes_decrypt(
    encrypted: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Result<Vec<u8>, block_modes::BlockModeError> {
    let cipher =
        Cbc::<Aes128, Pkcs7>::new_from_slices(key, iv).map_err(|_| block_modes::BlockModeError)?;
    cipher.decrypt_vec(encrypted)
}

// fn replace_string(rnd: u8) -> String {
//     if rnd > 235 {
//         '齁'.to_string()
//     } else if rnd > 175 {
//         '哦'.to_string()
//     } else if rnd > 152 {
//         '噢'.to_string()
//     } else if rnd > 93 {
//         '喔'.to_string()
//     } else if rnd > 58 {
//         '啊'.to_string()
//     } else if rnd > 21 {
//         '呱'.to_string()
//     } else {
//         '呼'.to_string()
//     }
// }

//
// fn shuffle_str(s: &str) -> String {
//     let mut chars: Vec<char> = s.chars().collect();
//     let mut rng = thread_rng();
//     chars.shuffle(&mut rng);
//     chars.into_iter().collect()
// }
//
// fn vigenere_encrypt(text: &str, key: &str) -> String {
//     let key_bytes = key.as_bytes();
//     let key_len = key_bytes.len();
//     text.chars()
//         .enumerate()
//         .map(|(i, c)| {
//             let shift = key_bytes[i % key_len] as u32;
//             std::char::from_u32((c as u32 + shift) % 0x9FA5).unwrap_or(c)
//         })
//         .collect()
// }
//
// fn generate_passwd(inpuu: u64, chux: u64) -> char {
//     match inpuu / chux % 35 {
//         0 => '0',
//         1 => '1',
//         2 => '2',
//         3 => '3',
//         4 => '4',
//         5 => '5',
//         6 => '6',
//         7 => '7',
//         8 => '8',
//         9 => '9',
//         10 => 'a',
//         11 => 'b',
//         12 => 'c',
//         13 => 'd',
//         14 => 'e',
//         15 => 'f',
//         16 => 'g',
//         17 => 'h',
//         18 => 'i',
//         19 => 'j',
//         20 => 'k',
//         21 => 'l',
//         22 => 'm',
//         23 => 'n',
//         24 => 'o',
//         25 => 'p',
//         26 => 'q',
//         27 => 'r',
//         28 => 's',
//         29 => 't',
//         30 => 'u',
//         31 => 'v',
//         32 => 'w',
//         33 => 'x',
//         34 => 'y',
//         _ => 'z',
//     }
// }
//
// / fn generate_passwd(inpuu: &BigInt, chux: &BigInt) -> char {
//     // 35 也变成 BigInt
//     let thirty_five = BigInt::from(35);
//     match ((inpuu / chux) % &thirty_five).to_u32().unwrap_or(0) {
//         0 => '0',
//         1 => '1',
//         2 => '2',
//         3 => '3',
//         4 => '4',
//         5 => '5',
//         6 => '6',
//         7 => '7',
//         8 => '8',
//         9 => '9',
//         10 => 'a',
//         11 => 'b',
//         12 => 'c',
//         13 => 'd',
//         14 => 'e',
//         15 => 'f',
//         16 => 'g',
//         17 => 'h',
//         18 => 'i',
//         19 => 'j',
//         20 => 'k',
//         21 => 'l',
//         22 => 'm',
//         23 => 'n',
//         24 => 'o',
//         25 => 'p',
//         26 => 'q',
//         27 => 'r',
//         28 => 's',
//         29 => 't',
//         30 => 'u',
//         31 => 'v',
//         32 => 'w',
//         33 => 'x',
//         34 => 'y',
//         _ => 'z',
//     }
// }
//
//     // if args.len() >= 2 {
//     let data_1 = args[1].as_bytes();
//     for i in data_1 {
//         data_1_1.push_str(&format!("{i}"));
//     }
//     // let tem_pas = data_1_1.parse::<u64>().unwrap_or_else(|_| {
//     //     eprintln!("错误: '{data_1_1}' 不是一个有效的数字");
//     //     std::process::exit(1);
//     // }) * local_time;
//     let tem_pas = BigInt::from_str_radix(&data_1_1, 10).unwrap_or_else(|_| {
//         eprintln!("错误: '{data_1_1}' 不是一个有效的数字");
//         std::process::exit(1);
//     }) * local_time;
//     // for i in 1..17 {
//     //     mima.push(generate_passwd(tem_pas, BigInt::from(i)));
//     // }
//     // for ii in 233..249 {
//     //     vi.push(generate_passwd(tem_pas, ii));
//     // }
//     for i in 1..17 {
//         mima.push(generate_passwd(&tem_pas, &BigInt::from(i)));
//     }
//     for ii in 233..249 {
//         vi.push(generate_passwd(&tem_pas, &BigInt::from(ii)));
//     }
// } else {
//     for i in 1..17 {
//         mima.push(generate_passwd(&local_time, &BigInt::from(i)));
//     }
//     for ii in 233..249 {
//         vi.push(generate_passwd(&local_time, &BigInt::from(ii)));
//     }
// }
// println!("mima: {mima} , vi: {vi}");
