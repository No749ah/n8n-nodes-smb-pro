import type { ICredentialType, INodeProperties } from 'n8n-workflow';

export class SmbApi implements ICredentialType {
	name = 'smbApi';

	displayName = 'SMB Share';

	documentationUrl = '';

	properties: INodeProperties[] = [
		{
			displayName: 'Host',
			name: 'host',
			type: 'string',
			default: '',
			required: true,
			placeholder: 'e.g. 192.168.1.10 or fileserver.example.com',
			description: 'IP address or hostname of the SMB server (without \\\\ prefix and without share name)',
		},
		{
			displayName: 'Share Name',
			name: 'share',
			type: 'string',
			default: '',
			required: true,
			placeholder: 'e.g. documents or archive$',
			description:
				'Name of the SMB share. Hidden shares ending with $ are supported. Do not include leading or trailing slashes.',
		},
		{
			displayName: 'Domain',
			name: 'domain',
			type: 'string',
			default: '',
			placeholder: 'e.g. CORP',
			description: 'Active Directory domain (NetBIOS short form, e.g. CORP). Leave empty for local accounts.',
		},
		{
			displayName: 'Username',
			name: 'username',
			type: 'string',
			default: '',
			required: true,
			description: 'Username only, without DOMAIN\\ prefix',
		},
		{
			displayName: 'Password',
			name: 'password',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
		},
		{
			displayName: 'Connection Timeout (ms)',
			name: 'timeout',
			type: 'number',
			default: 15000,
			description: 'Timeout for establishing the connection, in milliseconds',
		},
	];
}
