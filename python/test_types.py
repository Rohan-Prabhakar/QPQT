import sys
sys.path.insert(0, '/tmp')
import qpqt

pub, sec = qpqt.keygen()
kid = qpqt.generate_key_id()

w = qpqt.Writer('/tmp/test_types.qpqt',
    ['id', 'amount', 'score', 'city', 'ssn', 'dob'],
    ['int32', 'int64', 'float64', 'string', 'string', 'date32'],
    ['ssn'], pub, kid)

w.write_batch({
    'id':     [1, 2, 3],
    'amount': [100000, 200000, 300000],
    'score':  [9.5, 7.2, 8.8],
    'city':   ['NYC', 'LON', 'TYO'],
    'ssn':    ['SSN-A', 'SSN-B', 'SSN-C'],
    'dob':    [10957, 7470, 15000],
}, 3)
w.close()

r = qpqt.Reader('/tmp/test_types.qpqt')
r.set_secret_key(sec)
d = r.query()

assert d['id'][0] == 1,                   f"id: {d['id'][0]}"
assert d['amount'][0] == 100000,          f"amount: {d['amount'][0]}"
assert abs(d['score'][0] - 9.5) < 0.001, f"score: {d['score'][0]}"
assert d['city'][0] == 'NYC',             f"city: {d['city'][0]}"
assert d['ssn'][0] == 'SSN-A',            f"ssn: {d['ssn'][0]}"
assert d['dob'][0] == 10957,              f"dob: {d['dob'][0]}"
assert d['city'][2] == 'TYO',             f"city[2]: {d['city'][2]}"
assert d['ssn'][2] == 'SSN-C',            f"ssn[2]: {d['ssn'][2]}"

print('ALL TYPES PASS')
print('id:',     d['id'])
print('amount:', d['amount'])
print('score:',  [round(x,2) for x in d['score']])
print('city:',   d['city'])
print('ssn:',    d['ssn'])
print('dob:',    d['dob'])
print()
print('Schema:', qpqt.Reader('/tmp/test_types.qpqt').schema())
