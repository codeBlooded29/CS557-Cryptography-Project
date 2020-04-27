#include <bits/stdc++.h>
using namespace std;
typedef long long ll;

const ll MOD = 1000000007LL;
struct point
{
    ll x, y;
    point()
    {
        x = 0;
        y = 0;
    }
    point(ll a, ll b)
    {
        x = a;
        y = b;
    }
};
// elliptic curve parameters y^2 = x^3 + ax + b
ll a, b;

// random value for each transaction
ll k;
ll fast_exp(ll base, ll exp)
{
    if (exp == 0)
    {
        return 1LL;
    }

    ll res = 1;
    while (exp > 0)
    {
        if (exp % 2 == 1)
            res = (res * base) % MOD;
        base = (base * base) % MOD;
        exp /= 2;
    }
    res += MOD;
    return res % MOD;
}

ll getInverse(ll n)
{
    return fast_exp(n, MOD - 2);
}

ll divide(ll a, ll b)
{
    a = a % MOD;
    b = b % MOD;
    ll res = ((a * getInverse(b)) % MOD) % MOD;
    res += MOD;
    return res % MOD;
}

ll calcLambda(point p1, point p2)
{

    ll numerator = p2.y - p1.y;
    numerator += MOD;
    numerator %= MOD;

    ll denominator = p2.x - p1.x;
    denominator += MOD;
    denominator %= MOD;

    ll lambda = divide(numerator, denominator);
    lambda %= MOD;
    lambda += MOD;
    return lambda % MOD;
}

point pt_double(point p)
{
    point out;

    ll l = (((3 * fast_exp(p.x, 2)) % MOD) + a) % MOD;
    l += MOD;
    l %= MOD;

    ll d = (2 * p.y) % MOD;
    d += MOD;
    d %= MOD;

    l = divide(l, d);
    l += MOD;
    l %= MOD;

    out.x = (fast_exp(l, 2) - 2 * p.x) % MOD;
    out.x += MOD;
    out.x %= MOD;

    out.y = (((l * (p.x - out.x)) % MOD) - p.y) % MOD;
    out.y += MOD;
    out.y %= MOD;

    return out;
}

point pt_add(point p1, point p2)
{
    if (p1.x == p2.x && p1.y == p2.y)
    {
        return pt_double(p1);
    }

    point p3;

    ll lambda = calcLambda(p1, p2);

    p3.x = (fast_exp(lambda, 2) - p1.x - p2.x) % MOD;
    p3.x += MOD;
    p3.x %= MOD;

    p3.y = (((lambda * (p1.x - p3.x)) % MOD) - p1.y) % MOD;
    p3.y += MOD;
    p3.y %= MOD;

    return p3;
}

point pt_mul(point p, ll k)
{
    if (k == 2)
    {
        return pt_double(p);
    }

    point ans(p.x, p.y);
    k--;

    // fast multiplication
    while (k > 0)
    {
        if (k % 2 == 1)
        {
            ans = pt_add(ans, p);
        }
        p = pt_double(p);
        k /= 2;
    }
    return ans;
}

point encrypt(point m, ll k, point pub_key)
{
    point rv = pt_mul(pub_key, k);
    rv = pt_add(m, rv);
    return rv;
}

point decrypt(point c, point kG, ll priv_key)
{
    point m = pt_mul(kG, priv_key);
    m.y *= -1;
    m.y += MOD;
    m.y %= MOD;
    m = pt_add(c, m);
    return m;
}

int main()
{
    srand(time(NULL));

    //curve parameters
    a = 1;
    b = 4;

    ll nB;
    cout << "Enter receiver's private key (a 32-bit decimal number) : ";
    cin >> nB;

    point G(0, 2);

    string msg = "";
    cout << "Enter the text to be encrypted : ";
    getchar();
    getline(cin, msg);

    vector<point> msg_arr;
    for (ll i = 0; i < msg.length(); i++)
    {
        point P_M(msg[i], 0);
        msg_arr.push_back(P_M);
    }

    point P_B = pt_mul(G, nB);

    int k = rand() % MOD;
    if (k == 0)
    {
        k++;
    }
    point kG = pt_mul(G, k);

    cout << "Receiver's Public Key : (" << P_B.x << ", " << P_B.y << ")" << endl;

    // Doing character by character encryption
    vector<point> msg_encryp_arr;
    for (ll i = 0; i < msg.length(); i++)
    {
        msg_encryp_arr.push_back(encrypt(msg_arr[i], k, P_B));
    }

    vector<point> msg_decryp_arr;
    for (ll i = 0; i < msg.length(); i++)
    {
        msg_decryp_arr.push_back(decrypt(msg_encryp_arr[i], kG, nB));
    }

    cout << "Decrpyted text : ";
    for (int i = 0; i < msg.length(); i++)
    {
        char ch = msg_decryp_arr[i].x;
        cout << ch;
    }
    cout << endl;
}
