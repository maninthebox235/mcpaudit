'use strict';

// Intentional unsafe eval for scanner fixture coverage
function run(code) {
  return eval(code);
}

module.exports = { run };
