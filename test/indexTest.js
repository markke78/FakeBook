const assert = require('chai').assert;
const index = require('../index');

describe('Index', function() {
    it('app should return hello', function() {
        assert.equal(index(), 'hello')
    })
})




const object = {item1: 1, item2: 2, item3: 3}

expect(object.item1).to.equal(3)