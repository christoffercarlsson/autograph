use autograph::{Autograph, Bytes};

#[test]
fn test_calculate_safety_number() {
    let alice_public_key: Bytes = vec![
        91, 119, 85, 151, 32, 20, 121, 20, 19, 106, 90, 56, 141, 90, 16, 210, 14, 244, 60, 251,
        140, 48, 190, 65, 194, 35, 166, 246, 1, 209, 4, 33,
    ];
    let bob_public_key: Bytes = vec![
        232, 130, 200, 162, 218, 101, 75, 210, 196, 152, 235, 97, 118, 3, 241, 131, 200, 140, 54,
        155, 28, 46, 158, 76, 96, 4, 150, 61, 34, 13, 133, 138,
    ];
    let safety_number: Bytes = vec![
        52, 52, 57, 52, 50, 50, 53, 55, 54, 50, 48, 53, 51, 51, 49, 55, 56, 54, 48, 50, 55, 53, 56,
        48, 54, 52, 56, 52, 53, 49, 53, 55, 50, 49, 50, 54, 49, 50, 50, 49, 57, 52, 53, 57, 52, 50,
        55, 54, 49, 49, 54, 49, 57, 50, 52, 53, 52, 57, 50, 54,
    ];
    let autograph = Autograph::new().unwrap();
    let a = autograph
        .calculate_safety_number(&alice_public_key, &bob_public_key)
        .unwrap();
    let b = autograph
        .calculate_safety_number(&bob_public_key, &alice_public_key)
        .unwrap();
    assert_eq!(a, safety_number);
    assert_eq!(b, safety_number);
}
