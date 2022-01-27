var WhitelistOracle = artifacts.require("WhitelistOracle");

module.exports = function(deployer) {
  deployer.deploy(WhitelistOracle);
};