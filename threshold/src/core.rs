use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use threshold_crypto::{
    Ciphertext, DecryptionShare, PublicKey, PublicKeySet, PublicKeyShare, SecretKey, SecretKeySet,
    SecretKeyShare,
};

use thiserror::Error as ThisError;

/// Error type for the module, using `thiserror` for easy error handling.
#[derive(ThisError, Debug)]
pub enum Error {
    /// Indicates an invalid public key.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    /// Indicates an invalid private key.
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    /// Indicates an invalid ciphertext.
    #[error("Invalid cipher text: {0}")]
    InvalidCiphertext(String),
    /// Could not find the key in the keyset.
    #[error("Key not found")]
    KeyNotFound,
    /// No quorum of shares available.
    /// This error is returned when the number of shares is less than the threshold.
    #[error("No quorum")]
    NoQuorum,
    /// General error for internal issues.
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(Clone, Debug)]
pub struct PublicKeySetMsg(PublicKeySet);

impl PublicKeySetMsg {
    /// Creates a new `PublicKeySetMsg` instance from the given public key set.
    pub fn new(public_key_set: PublicKeySet) -> Self {
        PublicKeySetMsg(public_key_set)
    }

    /// Returns the underlying public key set.
    pub fn get_public_key_set(&self) -> &PublicKeySet {
        &self.0
    }
}

/// Wrapper for the public key, which is a serialized version of the public key.
#[derive(Clone, Debug)]
pub struct PubKey(PublicKey);

impl PubKey {
    /// Creates a new `PubKey` instance from the given public key.
    pub fn new(public_key: PublicKey) -> Self {
        PubKey(public_key)
    }

    /// Creates a new `PubKey` instance from the given byte array.
    pub fn new_from_bytes(bytes: [u8; 48]) -> Result<Self, Error> {
        PublicKey::from_bytes(bytes)
            .map(PubKey)
            .map_err(|e| Error::InvalidPublicKey(format!("Failed to create public key: {}", e)))
    }

    /// Returns the underlying public key.
    pub fn get_public_key(&self) -> &PublicKey {
        &self.0
    }
}

#[derive(Clone)]
pub struct DecryptionShareMsg(DecryptionShare);

impl DecryptionShareMsg {
    /// Creates a new `DecryptionShareMsg` instance from the given decryption share.
    pub fn new(decryption_share: DecryptionShare) -> Self {
        DecryptionShareMsg(decryption_share)
    }

    /// Returns the underlying decryption share.
    pub fn get_decryption_share(&self) -> &DecryptionShare {
        &self.0
    }
}

/// Wrapper for the ciphertext message, which is a serialized version of the ciphertext.
#[derive(Clone)]
pub struct CiphertextMsg(Ciphertext);

impl CiphertextMsg {
    /// Creates a new `CiphertextMsg` instance from the given ciphertext.
    pub fn new(ciphertext: Ciphertext) -> Self {
        CiphertextMsg(ciphertext)
    }

    /// Returns the underlying ciphertext.
    pub fn get_ciphertext(&self) -> &Ciphertext {
        &self.0
    }
}

/// Encrypt a message using the public key.
pub fn encrypt(public_key: &PublicKey, msg: &[u8]) -> CiphertextMsg {
    let ciphertext = public_key.encrypt(msg);
    CiphertextMsg::new(ciphertext)
}

/// Decrypt a message using the secret key.
pub fn decrypt(secret_key: &SecretKey, ciphertext: &Ciphertext) -> Option<Vec<u8>> {
    secret_key.decrypt(ciphertext)
}

/// Generate a new keyset with the given threshold
pub fn new_keyset(threshold: usize) -> SecretKeySet {
    let mut rng = rand::thread_rng();
    SecretKeySet::random(threshold, &mut rng)
}

/// Generate a new private key
pub fn new_private_key() -> SecretKey {
    SecretKey::random()
}

/// The `Committee` struct represents a group of actors (or actors) that can perform decryption
/// using a threshold secret sharing scheme.
/// The committee is created once by generating a keyset and then each actor is assigned a share of the secret key.
#[derive(Debug)]
pub struct Committee {
    pub actors: Vec<Actor>,
    pub pk_set: PublicKeySet,
}

impl Committee {
    // Creates a new `Committee`.
    // Accepts the number of actors (`n`) and the `threshold` (for decrypting a message) as parameters.
    pub fn new(n: usize, threshold: usize) -> Self {
        let sk_set = new_keyset(threshold);
        let pk_set = sk_set.public_keys();

        let actors = (0..n)
            .map(|id| {
                let sk_share = sk_set.secret_key_share(id);
                let pk_share = pk_set.public_key_share(id);
                Actor::new(id, Some(sk_share), pk_share)
            })
            .collect();

        Committee { actors, pk_set }
    }

    pub fn get_actor(&mut self, id: usize) -> &mut Actor {
        self.actors
            .get_mut(id)
            .expect("No `Actor` exists with that ID")
    }
}

/// The `Actor` struct represents an actor in the committee.
/// Each actor has a unique ID, a secret key share (optional), and a public key share.
#[derive(Clone, Debug)]
pub struct Actor {
    pub id: usize,
    pub sk_share: Option<SecretKeyShare>,
    pub pk_share: PublicKeyShare,
}

impl Actor {
    /// Creates a new `Actor` instance with the given ID, secret key share, and public key share.
    pub fn new(id: usize, sk_share: Option<SecretKeyShare>, pk_share: PublicKeyShare) -> Self {
        Actor {
            id,
            sk_share,
            pk_share,
        }
    }

    /// Decrypts a ciphertext using the actor's secret key share.
    pub fn decrypt_share(&self, ciphertext: Ciphertext) -> Result<DecryptionShare, Error> {
        let sk_share = self
            .sk_share
            .as_ref()
            .ok_or_else(|| Error::InternalError("No secret key share available".to_string()))?;
        let dec_share = sk_share.decrypt_share_no_verify(&ciphertext);

        if !self
            .pk_share
            .verify_decryption_share(&dec_share, &ciphertext)
        {
            return Err(Error::InternalError(
                "Decryption share verification failed".to_string(),
            ));
        }
        Ok(dec_share)
    }
}

/// The `ShareCollector` struct is a thread-safe in-mem store for decryption/signature shares that
/// were collected from committee actors.
#[derive(Clone)]
pub struct ShareCollector<T>
where
    T: Clone + Send + Sync + 'static,
{
    shares: Arc<RwLock<BTreeMap<usize, T>>>,
    threshold: usize,
}

impl<T> ShareCollector<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Creates a new `ShareCollector` instance with the given public key set.
    pub fn new(threshold: usize) -> Self {
        ShareCollector {
            shares: Arc::new(RwLock::new(BTreeMap::new())),
            threshold,
        }
    }

    /// Adds a share to the collection.
    /// Returns `Ok(true)` if the number of shares exceeds the threshold, otherwise `Ok(false)`.
    pub fn add_share(&self, id: usize, share: T) -> Result<bool, Error> {
        let mut shares = self.shares.write().map_err(|_| {
            Error::InternalError("Failed to add share: could not acquire lock".to_string())
        })?;
        shares.entry(id).or_insert(share);
        Ok(shares.len() > self.threshold)
    }

    /// Checks if the collector has a quorum of shares
    pub fn has_quorum(&self) -> Result<bool, Error> {
        Ok(self.number_of_shares()? > self.threshold)
    }

    /// Returns the number of collected shares.
    pub fn len(&self) -> Result<usize, Error> {
        self.number_of_shares()
    }

    /// Checks if the collector is empty.
    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.number_of_shares()? == 0)
    }

    /// Clears all collected shares.
    pub fn clear(&self) -> Result<(), Error> {
        let mut shares = self.shares.write().map_err(|_| {
            Error::InternalError("Failed to clear shares: could not acquire lock".to_string())
        })?;
        shares.clear();
        Ok(())
    }

    /// Collects all shares and returns them as a BTreeMap.
    /// This method takes ownership of the shares, so the collector will be empty after this call.
    pub fn collect(&self) -> Result<BTreeMap<usize, T>, Error> {
        let mut shares = self.shares.write().map_err(|_| {
            Error::InternalError("Failed to collect shares: could not acquire lock".to_string())
        })?;
        // NOTE: std::mem::take replaces the BTreeMap inside the RwLock with an empty one and returns
        // the original map. This avoids cloning the data and ensures ownership is transferred
        let shares: BTreeMap<usize, T> = std::mem::take(&mut *shares);
        Ok(shares)
    }

    fn number_of_shares(&self) -> Result<usize, Error> {
        let shares = self.shares.read().map_err(|_| {
            Error::InternalError("Failed to read shares: could not acquire lock".to_string())
        })?;
        Ok(shares.len())
    }
}

/// The `Decryptors` struct is a thread-safe in-memory store for `ShareDecryptor` instances.
/// It allows for the management of multiple decryptors, each associated with a unique ID.
#[derive(Clone)]
pub struct Decryptors {
    index: Arc<RwLock<BTreeMap<usize, Arc<ShareDecryptor>>>>,
    pk_set: PublicKeySet,
}

impl Decryptors {
    /// Creates a new `Decryptors` instance.
    pub fn new(pk_set: PublicKeySet) -> Self {
        Decryptors {
            index: Arc::new(RwLock::new(BTreeMap::new())),
            pk_set,
        }
    }

    pub fn new_decryptor(&self, id: usize) -> Arc<ShareDecryptor> {
        let decryptor = Arc::new(ShareDecryptor::new(self.pk_set.clone()));
        self.add(id, decryptor.clone());
        decryptor.clone()
    }

    /// Adds a new `ShareDecryptor` to the collection.
    pub fn add(&self, id: usize, decryptor: Arc<ShareDecryptor>) {
        let mut index = self.index.write().unwrap();
        index.insert(id, decryptor);
    }

    /// Returns the `ShareDecryptor` for the given ID.
    pub fn get(&self, id: usize) -> Option<Arc<ShareDecryptor>> {
        let index = self.index.read().unwrap();
        index.get(&id).cloned()
    }

    /// Prune the decryptors up to the given id.
    pub fn prune(&self, id: usize) -> Result<(), Error> {
        let mut index = self.index.write().map_err(|_| {
            Error::InternalError("Failed to prune decryptors: could not acquire lock".to_string())
        })?;
        index.retain(|&k, _| k > id);
        Ok(())
    }

    /// Removes the `ShareDecryptor` with the given ID from the collection.
    pub fn remove(&self, id: usize) -> Result<(), Error> {
        let mut index = self.index.write().map_err(|_| {
            Error::InternalError("Failed to remove decryptor: could not acquire lock".to_string())
        })?;
        let _ = index.remove(&id);
        Ok(())
    }

    /// Checks if the decryptor with the given sequence number exists.
    /// If we fail to acquire the lock, we return false.
    pub fn has(&self, id: usize) -> bool {
        if let Ok(index) = self.index.read() {
            return index.contains_key(&id);
        }
        false
    }
}

/// The `ShareDecryptor` struct is responsible for aggregating decryption shares from committee actors using the `ShareCollector`,
/// and performing the decryption of the ciphertext once a threshold number of shares have been collected.
/// The ShareDecryptor is exposing an unopinionated API so that it can be used in different contexts and fit multiple use cases.
#[derive(Clone)]
pub struct ShareDecryptor {
    share_collector: ShareCollector<DecryptionShare>,
    pk_set: PublicKeySet,
}

impl ShareDecryptor {
    /// Creates a new `ShareDecryptor` instance with the given public key set.
    pub fn new(pk_set: PublicKeySet) -> Self {
        ShareDecryptor {
            share_collector: ShareCollector::new(pk_set.threshold()),
            pk_set,
        }
    }

    /// Returns the underlying ShareCollector.
    pub fn get_collector(&self) -> &ShareCollector<DecryptionShare> {
        &self.share_collector
    }

    /// Adds a decryption share to the collector.
    pub fn add_share(&self, id: usize, share: DecryptionShare) -> Result<bool, Error> {
        self.share_collector.add_share(id, share)
    }

    /// Checks if the collector has a quorum of shares.
    pub fn has_quorum(&self) -> Result<bool, Error> {
        self.share_collector.has_quorum()
    }

    /// Decrypts the given ciphertext using the collected decryption shares.
    /// Returns the decrypted message as a byte vector.
    pub fn decrypt(&self, ciphertext: Ciphertext) -> Result<Vec<u8>, Error> {
        if !self.share_collector.has_quorum()? {
            return Err(Error::NoQuorum);
        }
        let shares: BTreeMap<usize, DecryptionShare> = self.share_collector.collect()?;

        decrypt_threshold(&self.pk_set, &shares, &ciphertext)
    }
}

/// Decrypts the given ciphertext using the provided public key set and decryption shares.
/// Returns the decrypted message as a byte vector.
pub fn decrypt_threshold(
    pk_set: &PublicKeySet,
    shares: &BTreeMap<usize, DecryptionShare>,
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>, Error> {
    pk_set
        .decrypt(shares, ciphertext)
        .map_err(|e| Error::InternalError(format!("Failed to decrypt: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_keyset() {
        let sk_set = new_keyset(3);
        let pk_set = sk_set.public_keys();
        _ = pk_set.public_key();
    }

    #[test]
    fn test_decryptor() {
        let n = 7;
        let t = 5;
        let mut committee = Committee::new(n, t);
        let decryptor = ShareDecryptor::new(committee.pk_set.clone());

        let pk = committee.pk_set.public_key();
        let ciphertext = pk.encrypt(b"test-message");
        for i in 0..t + 1 {
            let actor = committee.get_actor(i);
            let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
            decryptor.add_share(i, dec_share).unwrap();
        }

        let decrypted = decryptor.decrypt(ciphertext).unwrap();
        assert_eq!(decrypted, b"test-message")
    }

    #[test]
    fn test_decryptor_without_threshold() {
        let n = 7;
        let t = 5;

        let mut committee = Committee::new(n, t);
        let decryptor = ShareDecryptor::new(committee.pk_set.clone());

        let pk = committee.pk_set.public_key();
        let ciphertext = pk.encrypt(b"test-message");
        for i in 0..t {
            let actor = committee.get_actor(i);
            let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
            decryptor.add_share(i, dec_share).unwrap();
        }
        assert!(!decryptor.has_quorum().unwrap());
        match decryptor.decrypt(ciphertext.clone()) {
            Err(_) => {}
            Ok(_) => {
                // fail the test
                assert!(
                    false,
                    "should be able to decrypt before threshold of decryption shares"
                )
            }
        }
        // add one more share
        let actor = committee.get_actor(t);
        let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
        decryptor.add_share(t, dec_share).unwrap();
        assert!(decryptor.has_quorum().unwrap());
        let decrypted = decryptor.decrypt(ciphertext).unwrap();
        assert_eq!(decrypted, b"test-message");
    }

    #[test]
    fn test_decryptor_wrong_ciphertext() {
        let n = 7;
        let t = 5;
        let mut committee = Committee::new(n, t);
        let decryptor = ShareDecryptor::new(committee.pk_set.clone());

        let pk = committee.pk_set.public_key();
        let ciphertext = pk.encrypt(b"test-message");
        for i in 0..t + 1 {
            let actor = committee.get_actor(i);
            let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
            decryptor.add_share(i, dec_share).unwrap();
        }

        let decrypted = decryptor.decrypt(pk.encrypt(b"wrong-message")).unwrap();
        assert_ne!(decrypted, b"test-message");
    }

    #[test]
    fn test_decryptor_fails_on_single_bad_share() {
        let n = 7;
        let t = 5;
        let mut committee = Committee::new(n, t);
        let mut some_other_committee = Committee::new(n, t);
        let decryptor = ShareDecryptor::new(committee.pk_set.clone());

        let pk = committee.pk_set.public_key();
        let ciphertext = pk.encrypt(b"test-message");
        for i in 0..t {
            let actor = committee.get_actor(i);
            let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
            println!("adding {i}, {}", t);
            decryptor.add_share(i, dec_share).unwrap();
        }

        // Add a bad share (from another committee)
        let actor = some_other_committee.get_actor(t);
        let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
        decryptor.add_share(t, dec_share).unwrap();

        let decrypted = decryptor.decrypt(ciphertext).unwrap();
        assert_ne!(decrypted, b"test-message")
    }
}
