document.getElementById('launchForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const ami_id = document.getElementById('ami_id').value;
    const instance_type = document.getElementById('instance_type').value;
    const count = document.getElementById('count').value;

//
    fetch(`/launch_instance?ami_id=${ami_id}&instance_type=${instance_type}&count=${count}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        alert(`Instance launched: ${data.instance_id}`);
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

document.getElementById('listInstancesButton').addEventListener('click', function() {
    fetch('/list_instances')
    .then(response => response.json())
    .then(data => {
        const instancesList = document.getElementById('instancesList');
        instancesList.innerHTML = '<h3>Instances:</h3>';
        data.instances.forEach(instance => {
            instancesList.innerHTML += `<p>ID: ${instance.instance_id}, Type: ${instance.instance_type}, State: ${instance.state}</p>`;
        });
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

document.getElementById('instanceOperationForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const instance_id = document.getElementById('instance_id').value;
    const operation = document.getElementById('operation').value;
    let endpoint = '';

    if (operation === 'start') {
        endpoint = '/start_instance';
    } else if (operation === 'stop') {
        endpoint = '/stop_instance';
    } else if (operation === 'terminate') {
        endpoint = '/delete_instance';
    }

    fetch(`${endpoint}?instance_id=${instance_id}`, {
        method: 'PUT'
    })
    .then(response => response.json())
    .then(data => {
        alert(`Instance ${operation}d successfully`);
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

