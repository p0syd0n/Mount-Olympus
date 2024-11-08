import { Tree } from 'radix-tree';

// Initialize a radix tree
const productNamesTree = new Tree();

// Add words to the tree, associating each product name with its data
productNamesTree.add('smartphone', { id: 1, name: 'Smartphone' });
productNamesTree.add('smartwatch', { id: 2, name: 'Smartwatch' });
productNamesTree.add('smarthome', { id: 3, name: 'Smart Home Device' });
productNamesTree.add('speaker', { id: 4, name: 'Bluetooth Speaker' });
productNamesTree.add('scooter', { id: 5, name: 'Electric Scooter' });

// Prefix search function
function searchByPrefix(prefix) {
  const results = [];
  
  // Get the subtree starting at the given prefix
  const prefixNode = productNamesTree.find(prefix);
  
  // If no node found with that prefix, return empty array
  if (!prefixNode) return results;

  // Traverse the subtree and collect values
  prefixNode.children.forEach((node) => {
    results.push(node.value); // Collect all product data with this prefix
  });
  
  return results;
}

// Example usage
console.log(searchByPrefix('smart'));
// Output: Array of product objects that have names starting with 'smart'
