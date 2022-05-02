use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};
use std::fmt;

#[derive(Debug)]
pub enum PassphaseManageErr {
    PassphaseErr(PassphaseErr),
    ShareNumErr,
    ParseByteToShareErr(&'static str),
    RecoverFromSharesErr(String),
}

impl fmt::Display for PassphaseManageErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PassphaseManageErr::PassphaseErr(e) => write!(f, "{}", e),
            PassphaseManageErr::ShareNumErr => write!(f,"Number of share to create must be greater than required minimum number of shares to recover."),
            PassphaseManageErr::ParseByteToShareErr(e) => write!(f,"Failed to parse worlds to share: {}", e),
            PassphaseManageErr::RecoverFromSharesErr(e) => write!(f,"Failed to recover secret from shares: {}", e),
        }
    }
}

impl From<PassphaseErr> for PassphaseManageErr {
    fn from(e: PassphaseErr) -> Self {
        Self::PassphaseErr(e)
    }
}

pub fn get_share<'a>(
    passphrase: Passphrase<'a>,
    num_shares_to_create: u8,
    required_num_shares_to_recover: u8,
) -> Result<Vec<Vec<&'a str>>, PassphaseManageErr> {
    if num_shares_to_create <= required_num_shares_to_recover {
        return Err(PassphaseManageErr::ShareNumErr);
    }

    let sharks = Sharks(required_num_shares_to_recover);

    let key = passphrase.to_bytes()?;

    // Obtain an iterator over the shares for secret
    let dealer = sharks.dealer(&key);
    let shares: Vec<Share> = dealer.take(num_shares_to_create as usize).collect();

    let mut share_passphrases: Vec<Passphrase> = Vec::with_capacity(num_shares_to_create as usize);

    for share in shares {
        let share_bytes: Vec<u8> = Vec::from(&share);

        let p = Passphrase::from_bytes(&share_bytes)?;
        share_passphrases.push(p);
    }

    let mut share_passphrases_words: Vec<Vec<&'a str>> =
        Vec::with_capacity(num_shares_to_create as usize);

    for share_p in share_passphrases {
        let p_words = share_p.get_words()?;
        share_passphrases_words.push(p_words);
    }

    Ok(share_passphrases_words)
}

pub fn restore_from_share<'a>(
    shares_words: &Vec<Vec<&'a str>>,
) -> Result<Passphrase<'a>, PassphaseManageErr> {
    let num_share = shares_words.len() as usize;
    let mut shares: Vec<Share> = Vec::with_capacity(num_share);
    for share_words in shares_words {
        let p = Passphrase::from_words(share_words)?;
        let share = Share::try_from(p.to_bytes()?.as_slice())
            .map_err(|e| PassphaseManageErr::ParseByteToShareErr(e))?;

        shares.push(share);
    }

    let sharks = Sharks(num_share as u8);
    let secret = sharks
        .recover(&shares[0..num_share])
        .map_err(|e| PassphaseManageErr::RecoverFromSharesErr(e.to_string()))?;

    let passphase = Passphrase::from_bytes(&secret)?;
    Ok(passphase)
}

#[derive(Debug)]
pub enum PassphaseErr {
    InvalidWord,
    InvalidNumOfWord,
    PassphaseIsEmpty,
    Unexpected(String),
}

impl fmt::Display for PassphaseErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PassphaseErr::InvalidWord => write!(f, "Invalid world."),
            PassphaseErr::InvalidNumOfWord => write!(f, "Invalid number of word, expecting.",),
            PassphaseErr::PassphaseIsEmpty => write!(f, "Passphase is empty."),
            PassphaseErr::Unexpected(e) => write!(f, "Unexpected: {}", e),
        }
    }
}

pub struct Passphrase<'a> {
    wordlist: WordList<'a>,
    word_indexs: Vec<WordIndex>,
    /// Number of bit for the checksum.
    checksum_size: u8,
}

impl<'a> Passphrase<'a> {
    pub fn from_words(words: &Vec<&str>) -> Result<Self, PassphaseErr> {
        let len = words.len();
        if len != 12 && len != 13 && len != 24 && len != 25 {
            return Err(PassphaseErr::InvalidNumOfWord);
        }

        let wordlist = WordList::new();

        let mut word_indexs: Vec<WordIndex> = Vec::with_capacity(12);

        for word in words.iter() {
            let index = wordlist.get_index(word).ok_or(PassphaseErr::InvalidWord)?;
            word_indexs.push(index);
        }
        let checksum_size = match len {
            12usize => 4,
            13usize => 7,
            24usize => 8,
            25usize => 11,
            _ => {
                return Err(PassphaseErr::Unexpected(
                    "Invalid number of words".to_string(),
                ))
            }
        };

        Ok(Passphrase {
            wordlist,
            word_indexs,
            checksum_size: checksum_size as u8,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PassphaseErr> {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();

        let checksum_size = match bytes.len() {
            16usize => 4,
            17usize => 7,
            32usize => 8,
            33usize => 11,
            _ => {
                return Err(PassphaseErr::Unexpected(format!(
                    "Invalid number of bytes: {}",
                    bytes.len()
                )))
            }
        };

        let num_word = match bytes.len() {
            16usize => 12,
            17usize => 13,
            32usize => 24,
            33usize => 25,
            _ => {
                return Err(PassphaseErr::Unexpected(format!(
                    "Invalid number of bytes: {}",
                    bytes.len()
                )))
            }
        };
        let checksum = format!("{:08b}{:08b}", result[0], result[1]);
        let checksum = &checksum[..(checksum_size as usize)];

        let mut full_bits_str = String::with_capacity(bytes.len() * 8 + checksum_size);

        for byte in bytes {
            full_bits_str.push_str(&format!("{:08b}", byte));
        }
        // add checksum
        full_bits_str.push_str(&checksum);

        // Read into word index u16.
        let mut index_begin = 0;
        let mut index_end = 11;

        let mut word_indexs: Vec<WordIndex> = Vec::with_capacity(num_word as usize);

        while index_end <= full_bits_str.len() {
            let index_str = &full_bits_str[index_begin..index_end];
            let index = u16::from_str_radix(index_str, 2).map_err(|_| {
                PassphaseErr::Unexpected("Fail when parse binary string.".to_string())
            })?;

            index_begin = index_begin + 11;
            index_end = index_end + 11;

            word_indexs.push(WordIndex(index));
        }

        Ok(Passphrase {
            wordlist: WordList::new(),
            checksum_size: checksum_size as u8,
            word_indexs,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PassphaseErr> {
        let bit_len = self.word_indexs.len() * 11;
        let mut bit_str = String::with_capacity(bit_len);

        let word_indexs: &Vec<WordIndex> = self.word_indexs.as_ref();

        for index in word_indexs.iter() {
            let sub_bits = format!("{:011b}", index.0);
            bit_str.push_str(&sub_bits);
        }

        // remove the checksum
        let bit_str = &bit_str[..(bit_len - self.checksum_size as usize)];
        let mut byte_begin = 0;
        let mut byte_end = 8;

        let mut bytes: Vec<u8> = Vec::with_capacity(bit_len / 8);

        while byte_end <= bit_str.len() {
            let byte_str = &bit_str[byte_begin..byte_end];
            let byte = u8::from_str_radix(byte_str, 2).map_err(|_| {
                PassphaseErr::Unexpected("Fail when parse binary string.".to_string())
            })?;

            byte_begin = byte_begin + 8;
            byte_end = byte_end + 8;

            bytes.push(byte);
        }

        Ok(bytes)
    }

    pub fn get_words(&self) -> Result<Vec<&'a str>, PassphaseErr> {
        let mut words: Vec<&str> = Vec::with_capacity(self.word_indexs.len());

        let word_indexs: &Vec<WordIndex> = self.word_indexs.as_ref();

        for index in word_indexs.into_iter() {
            words.push(self.wordlist.get_word(index.clone()));
        }

        Ok(words)
    }
}

#[derive(Clone, PartialEq, Debug, Default)]
struct WordIndex(u16);

#[derive(Debug)]
struct WordIndexOutOfRange;

impl std::fmt::Display for WordIndexOutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Invalid index range max range is 2^11.")
    }
}

struct WordList<'a> {
    words: Vec<&'a str>,
}

impl<'a> WordList<'a> {
    fn new() -> Self {
        let words = WordList::load_world_list();
        Self { words }
    }

    fn load_world_list() -> Vec<&'a str> {
        let worldlist = include_str!("./worldlist.txt");
        worldlist.lines().collect()
    }

    fn get_word(&self, i: WordIndex) -> &'a str {
        self.words[i.0 as usize]
    }

    fn get_index(&self, word: &str) -> Option<WordIndex> {
        self.words
            .iter()
            .position(|&w| w == word)
            .map(|s| WordIndex(s as u16))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_world() {
        let word_list = WordList::new();
        let index1 = WordIndex::new(0).unwrap();
        let index_last = WordIndex::new((2u16).pow(11) - 1).unwrap();
        assert_eq!(word_list.get_word(index1), "abandon");
        assert_eq!(word_list.get_word(index_last), "zoo");
    }

    #[test]
    fn test_get_index() {
        let word_list = WordList::new();
        let index1 = word_list.get_index("abandon").unwrap();
        let index_last = word_list.get_index("zoo").unwrap();
        assert!(index1 == WordIndex(0));
        assert!(index_last == WordIndex((2u16).pow(11) - 1));
    }

    #[test]
    fn test_passphase_to_bytes() {
        assert_eq!("hello", "hello");
    }

    #[test]
    fn test_parse_passphase_to_bytes() {
        let pp: Vec<&str> =
            "gold dress spread awful floor expect ladder high better census indicate today"
                .split(" ")
                .collect();
        let bytes = Passphrase::from_words(&pp).unwrap().to_bytes().unwrap();

        let expected: [u8; 16] = [
            100, 72, 87, 76, 8, 85, 150, 160, 159, 27, 92, 21, 132, 169, 203, 241,
        ];
        assert_eq!(bytes, expected);

        let pp: [&str; 13] = [
            "accuse", "sad", "ball", "wear", "right", "wife", "wrap", "satoshi", "speed", "oil",
            "festival", "margin", "genius",
        ];

        let expected: [u8; 17] = [
            1, 183, 180, 71, 252, 59, 157, 245, 255, 133, 251, 209, 19, 57, 84, 195, 246,
        ];

        let bytes = Passphrase::from_words(&pp.to_vec())
            .unwrap()
            .to_bytes()
            .unwrap();

        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_passphrase_from_bytes() {
        let pp: Vec<&str> =
            "gold dress spread awful floor expect ladder high better census indicate today"
                .split(" ")
                .collect();

        let bytes: [u8; 16] = [
            100, 72, 87, 76, 8, 85, 150, 160, 159, 27, 92, 21, 132, 169, 203, 241,
        ];
        let passphase = Passphrase::from_bytes(&bytes).unwrap();

        let words = passphase.get_words().unwrap();
        assert_eq!(words, pp);
    }

    #[test]
    fn test_get_share_and_restore() {
        let samples = [
       "gold dress spread awful floor expect ladder high better census indicate today",
       "collect chest library deal split author sister loan relax acid estate deal",
         "mixed devote sponsor swift wonder assault lizard normal similar marriage dirt swallow",
         "water butter winter milk acid circle zoo clutch erosion mail swim entry",
          "put slim hunt lyrics shy opera ecology hole human gloom tackle shuffle similar smart joke retreat juice lottery sign horn peanut vast bicycle mushroom",
        ];

        for sample in samples {
            let pp: Vec<&str> = sample.split(" ").collect();
            let pp = Passphrase::from_words(&pp).expect("Failed to parse passphrase");

            let shares = get_share(pp, 2, 1).expect("Failed to generate shares.");
            let pp = restore_from_share(&shares[0..1].to_vec()).expect("Failed to retore share");
            let ws = pp.get_words().expect("Failed to get words");
            let ws = ws.join(" ");
            assert_eq!(ws, sample);
        }
    }
}
